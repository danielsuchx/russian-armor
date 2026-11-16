#!/usr/bin/env python3
"""Validate explicit signing inputs and prepare private protected-build metadata.

This does not request profiles, modify a keychain, contact a developer service,
install an extension or enable a VPN. The OS still validates provisioning and
requests user approval when the finished application installs its extension.
"""

import argparse
import datetime as dt
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import uuid


APP_ID = "app.russian-armour.desktop"
PROXY_ID = APP_ID + ".proxy"
CAPABILITY_KEY = "com.apple.developer.networking.networkextension"
SYSTEM_CAPABILITY = "app-proxy-provider-systemextension"
DEVELOPMENT_CAPABILITY = "app-proxy-provider"
USAGE_DESCRIPTION = "Russian Armour направляет соединения Claude через защищённый канал и блокирует их при его недоступности."


class SigningError(Exception):
    pass


def utc(value):
    if not isinstance(value, dt.datetime):
        raise SigningError("В provisioning profile отсутствует дата действия.")
    return value.replace(tzinfo=dt.timezone.utc) if value.tzinfo is None else value.astimezone(dt.timezone.utc)


def resolve_identity(requested):
    if not requested or requested == "-":
        raise SigningError("Укажите Apple Development или Developer ID signing identity; ad-hoc подпись не поддерживается.")
    result = subprocess.run(
        ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
        check=True, capture_output=True, text=True,
    )
    identities = re.findall(r'^\s*\d+\) ([0-9A-Fa-f]{40}) "([^"]+)"\s*$', result.stdout, re.MULTILINE)
    matching = [(fingerprint.upper(), name) for fingerprint, name in identities
                if requested.upper() == fingerprint.upper() or requested == name]
    if len(matching) != 1:
        raise SigningError("ARMOUR_SIGNING_IDENTITY должна однозначно совпадать с полной SHA-1 или полным именем действующей codesigning identity в Связке ключей.")
    fingerprint, name = matching[0]
    if not name.startswith(("Apple Development:", "Mac Developer:", "Developer ID Application:")):
        raise SigningError("Для этой сборки нужна Apple Development или Developer ID Application identity.")
    return fingerprint, name


def decode_profile(path, label, verifier):
    try:
        encoded = Path(path).read_bytes()
    except OSError as error:
        raise SigningError(f"Не удалось прочитать {label} provisioning profile.") from error
    if not 1 <= len(encoded) <= 2 * 1024 * 1024:
        raise SigningError(f"Некорректный размер {label} provisioning profile.")
    verified = subprocess.run([str(verifier)], input=encoded, capture_output=True)
    if verified.returncode:
        raise SigningError(f"Подпись Apple в {label} provisioning profile не прошла проверку.")
    # Decode the exact bytes later embedded in the bundle, avoiding a second
    # read of a source profile that could change between validation and copying.
    result = subprocess.run(["/usr/bin/security", "cms", "-D"], input=encoded, capture_output=True)
    if result.returncode:
        raise SigningError(f"security cms не смог декодировать {label} provisioning profile.")
    try:
        profile = plistlib.loads(result.stdout)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise SigningError(f"{label} provisioning profile не содержит корректный plist.") from error
    if not isinstance(profile, dict):
        raise SigningError(f"Некорректный {label} provisioning profile.")
    return profile, encoded


def authorizes_keychain_group(grants, group, team):
    if not isinstance(grants, list):
        return False
    for grant in grants:
        if not isinstance(grant, str):
            continue
        if grant == group:
            return True
        # Apple keychain grants may use a trailing wildcard under the team.
        # Arbitrary shell-style patterns and an unscoped '*' are not accepted.
        if grant.startswith(team + ".") and grant.endswith("*") and grant.count("*") == 1:
            if group.startswith(grant[:-1]):
                return True
    return False


def validate_profile(profile, *, bundle_id, fingerprint, identity_name, now=None, distribution=False):
    label = "приложения" if bundle_id == APP_ID else "расширения"
    now = utc(now or dt.datetime.now(dt.timezone.utc))
    if utc(profile.get("ExpirationDate")) <= now:
        raise SigningError(f"Provisioning profile {label} истёк.")
    if profile.get("CreationDate") is not None and utc(profile["CreationDate"]) > now + dt.timedelta(minutes=5):
        raise SigningError(f"Provisioning profile {label} ещё не действует.")
    platforms = profile.get("Platform")
    if not isinstance(platforms, list) or not set(platforms).intersection({"OSX", "macOS"}):
        raise SigningError(f"Provisioning profile {label} должен быть для macOS.")
    teams = profile.get("TeamIdentifier")
    if not isinstance(teams, list) or len(teams) != 1 or not isinstance(teams[0], str) or not re.fullmatch(r"[A-Z0-9]{10}", teams[0]):
        raise SigningError(f"Некорректный TeamIdentifier в profile {label}.")
    team = teams[0]
    if distribution and (
        not identity_name.startswith("Developer ID Application:")
        or profile.get("ProvisionsAllDevices") is not True
    ):
        raise SigningError("Release требует Developer ID Application и Developer ID provisioning profiles. Для локальной разработки используйте debug.")
    entitlements = profile.get("Entitlements")
    if not isinstance(entitlements, dict) or entitlements.get("com.apple.developer.team-identifier") != team:
        raise SigningError(f"TeamIdentifier не совпадает с entitlements profile {label}.")
    expected_id = team + "." + bundle_id
    identifiers = [entitlements[key] for key in ("com.apple.application-identifier", "application-identifier") if key in entitlements]
    if not identifiers or any(value != expected_id for value in identifiers):
        raise SigningError(f"Profile {label} должен разрешать точный App ID {expected_id}; wildcard App ID не подходит.")
    certificates = profile.get("DeveloperCertificates")
    if not isinstance(certificates, list) or not any(
        isinstance(certificate, bytes) and hashlib.sha1(certificate).hexdigest().upper() == fingerprint.upper()
        for certificate in certificates
    ):
        raise SigningError(f"Выбранный signing certificate не включён в provisioning profile {label}.")
    capabilities = entitlements.get(CAPABILITY_KEY)
    if not isinstance(capabilities, list):
        raise SigningError(f"Provisioning profile {label} не разрешает Network Extension.")
    if SYSTEM_CAPABILITY in capabilities:
        capability = SYSTEM_CAPABILITY
    elif not distribution and DEVELOPMENT_CAPABILITY in capabilities and identity_name.startswith(("Apple Development:", "Mac Developer:")) and (
        entitlements.get("get-task-allow") is True or entitlements.get("com.apple.security.get-task-allow") is True
    ):
        # Apple describes the '-systemextension' value specifically for
        # Developer ID profiles. Local development can use the development
        # value only when the development identity and profile both grant it.
        capability = DEVELOPMENT_CAPABILITY
    else:
        raise SigningError(f"Profile {label} не разрешает app-proxy-provider-systemextension (или development app-proxy-provider для Apple Development).")
    group = team + ".app.russian-armour.shared"
    if not authorizes_keychain_group(entitlements.get("keychain-access-groups"), group, team):
        raise SigningError(f"Profile {label} не разрешает общую keychain access group {group}.")
    if bundle_id == APP_ID and entitlements.get("com.apple.developer.system-extension.install") is not True:
        raise SigningError("Profile приложения не разрешает com.apple.developer.system-extension.install.")
    if bundle_id == PROXY_ID and entitlements.get("com.apple.security.app-sandbox") is False:
        raise SigningError("Profile расширения запрещает необходимый App Sandbox.")
    return team, capability


def substitute(value, replacements):
    if isinstance(value, str):
        for old, new in replacements.items():
            value = value.replace(old, new)
        if "$(" in value:
            raise SigningError("В metadata осталась нераскрытая переменная сборки.")
        return value
    if isinstance(value, list):
        return [substitute(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, replacements) for key, item in value.items()}
    return value


def write_plist(path, value):
    path.write_bytes(plistlib.dumps(value, sort_keys=False))
    path.chmod(0o600)


def prepare(args):
    fingerprint, identity_name = resolve_identity(args.identity)
    verifier = Path(args.profile_verifier)
    if not verifier.is_file() or not os.access(verifier, os.X_OK):
        raise SigningError("Не найден исполняемый Apple CMS verifier.")
    app_profile, app_encoded = decode_profile(args.app_profile, "приложения", verifier)
    proxy_profile, proxy_encoded = decode_profile(args.proxy_profile, "расширения", verifier)
    distribution = args.configuration == "release"
    app_team, app_capability = validate_profile(app_profile, bundle_id=APP_ID, fingerprint=fingerprint, identity_name=identity_name, distribution=distribution)
    proxy_team, proxy_capability = validate_profile(proxy_profile, bundle_id=PROXY_ID, fingerprint=fingerprint, identity_name=identity_name, distribution=distribution)
    if app_team != proxy_team:
        raise SigningError("Приложение и расширение должны использовать одну Apple developer team.")
    output = Path(args.output)
    if not output.is_dir():
        raise SigningError("Каталог private staging не существует.")
    support = Path(args.support)
    group = app_team + ".app.russian-armour.shared"
    app_info = plistlib.loads(Path(args.base_info).read_bytes())
    if app_info.get("CFBundleIdentifier") != APP_ID:
        raise SigningError("Неожиданный bundle ID приложения в Support/Info.plist.")
    app_info["ArmourKeychainAccessGroup"] = group
    app_info["NSSystemExtensionUsageDescription"] = USAGE_DESCRIPTION
    proxy_info = substitute(plistlib.loads((support / "ProxyInfo.plist").read_bytes()), {"$(TeamIdentifier)": app_team})
    proxy_info["ArmourKeychainAccessGroup"] = group
    for key in ("CFBundleVersion", "CFBundleShortVersionString", "LSMinimumSystemVersion"):
        proxy_info[key] = app_info[key]
    write_plist(output / "AppInfo.plist", app_info)
    write_plist(output / "ProxyInfo.plist", proxy_info)
    for name, bundle_id, capability in [("App", APP_ID, app_capability), ("Proxy", PROXY_ID, proxy_capability)]:
        value = plistlib.loads((support / (name + ".entitlements")).read_bytes())
        value = substitute(value, {"$(TeamIdentifier)": app_team, "$(NetworkExtensionCapability)": capability})
        value["com.apple.application-identifier"] = app_team + "." + bundle_id
        value["com.apple.developer.team-identifier"] = app_team
        if capability == DEVELOPMENT_CAPABILITY:
            profile = app_profile if name == "App" else proxy_profile
            for entitlement in ("get-task-allow", "com.apple.security.get-task-allow"):
                if profile["Entitlements"].get(entitlement) is True:
                    value[entitlement] = True
        write_plist(output / (name + ".entitlements"), value)
    (output / "App.provisionprofile").write_bytes(app_encoded)
    (output / "Proxy.provisionprofile").write_bytes(proxy_encoded)
    (output / "identity.sha1").write_text(fingerprint, encoding="ascii")
    for name in ("App.provisionprofile", "Proxy.provisionprofile", "identity.sha1"):
        (output / name).chmod(0o600)


def publish(args):
    source, destination = Path(args.source), Path(args.destination)
    if source.parent.parent.resolve() != destination.parent.resolve():
        raise SigningError("Staging bundle должен находиться на том же томе внутри каталога dist.")
    if not source.is_dir() or source.is_symlink() or destination.is_symlink():
        raise SigningError("Некорректный путь bundle для публикации.")
    if destination.exists() and not destination.is_dir():
        raise SigningError("Назначение существует и не является каталогом приложения.")
    backup = destination.with_name(".armour-previous-" + uuid.uuid4().hex + ".app")
    had_previous = destination.exists()
    if had_previous:
        destination.rename(backup)
    try:
        source.rename(destination)
    except OSError:
        if had_previous:
            backup.rename(destination)
        raise
    if had_previous:
        shutil.rmtree(backup)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    for flag in ("identity", "app-profile", "proxy-profile", "base-info", "support", "output", "profile-verifier"):
        preparation.add_argument("--" + flag, required=True)
    preparation.add_argument("--configuration", choices=("debug", "release"), required=True)
    publication = commands.add_parser("publish")
    publication.add_argument("--source", required=True)
    publication.add_argument("--destination", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        (prepare if args.command == "prepare" else publish)(args)
    except (SigningError, OSError, subprocess.SubprocessError, plistlib.InvalidFileException, ValueError, KeyError) as error:
        print("Protected build: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
