#!/usr/bin/env python3
"""Offline validation tests using fabricated profile metadata, never real keys."""

import datetime as dt
import hashlib
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("protection_signing", Path(__file__).with_name("protection_signing.py"))
signing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signing)


class ProfileValidationTests(unittest.TestCase):
    team = "EXAMPLE123"
    certificate = b"fabricated-public-certificate-not-a-real-certificate"
    fingerprint = hashlib.sha1(certificate).hexdigest().upper()
    identity = "Developer ID Application: Fixture (EXAMPLE123)"
    now = dt.datetime(2030, 1, 2, tzinfo=dt.timezone.utc)

    def profile(self, bundle_id=signing.APP_ID):
        return {
            "CreationDate": self.now - dt.timedelta(days=1),
            "ExpirationDate": self.now + dt.timedelta(days=1),
            "Platform": ["OSX"],
            "TeamIdentifier": [self.team],
            "ProvisionsAllDevices": True,
            "DeveloperCertificates": [self.certificate],
            "Entitlements": {
                "com.apple.application-identifier": self.team + "." + bundle_id,
                "com.apple.developer.team-identifier": self.team,
                signing.CAPABILITY_KEY: [signing.SYSTEM_CAPABILITY],
                "com.apple.developer.system-extension.install": True,
                "keychain-access-groups": [self.team + ".*"],
            },
        }

    def validate(self, profile, **kwargs):
        return signing.validate_profile(profile, bundle_id=kwargs.pop("bundle_id", signing.APP_ID),
                                        fingerprint=kwargs.pop("fingerprint", self.fingerprint),
                                        identity_name=kwargs.pop("identity_name", self.identity),
                                        now=self.now, **kwargs)

    def testExactAppAndExtensionProfilesAndScopedKeychainWildcard(self):
        self.assertEqual(self.validate(self.profile(), distribution=True), (self.team, signing.SYSTEM_CAPABILITY))
        self.assertEqual(self.validate(self.profile(signing.PROXY_ID), bundle_id=signing.PROXY_ID),
                         (self.team, signing.SYSTEM_CAPABILITY))

    def testRejectsExpiredWrongPlatformWrongCertificateAndWildcardAppID(self):
        for key, value in [("ExpirationDate", self.now), ("Platform", ["iOS"]),
                           ("DeveloperCertificates", [b"another-certificate"]), ("TeamIdentifier", ["OTHERTEAM1"])]:
            profile = self.profile()
            profile[key] = value
            with self.subTest(key=key), self.assertRaises(signing.SigningError):
                self.validate(profile)
        profile = self.profile()
        profile["Entitlements"]["com.apple.application-identifier"] = self.team + ".*"
        with self.assertRaises(signing.SigningError):
            self.validate(profile)

    def testRequiresInstallNetworkAndSharedKeychainCapabilities(self):
        for key, value in [("com.apple.developer.system-extension.install", False),
                           (signing.CAPABILITY_KEY, []),
                           ("keychain-access-groups", ["*"]),
                           ("keychain-access-groups", ["OTHERTEAM1.*"]),
                           ("keychain-access-groups", [self.team + ".another-group"])]:
            profile = self.profile()
            profile["Entitlements"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(signing.SigningError):
                self.validate(profile)

    def testDevelopmentCapabilityOnlyForDevelopmentIdentityAndProfile(self):
        profile = self.profile()
        profile["Entitlements"][signing.CAPABILITY_KEY] = [signing.DEVELOPMENT_CAPABILITY]
        profile["Entitlements"]["get-task-allow"] = True
        development_identity = "Apple Development: Fixture (EXAMPLE123)"
        self.assertEqual(self.validate(profile, identity_name=development_identity),
                         (self.team, signing.DEVELOPMENT_CAPABILITY))
        with self.assertRaises(signing.SigningError):
            self.validate(profile)
        with self.assertRaises(signing.SigningError):
            self.validate(profile, identity_name=development_identity, distribution=True)
        profile["Entitlements"]["get-task-allow"] = False
        with self.assertRaises(signing.SigningError):
            self.validate(profile, identity_name=development_identity)

    def testReleaseRequiresDeveloperIDAllDevicesProfile(self):
        profile = self.profile()
        with self.assertRaises(signing.SigningError):
            self.validate(profile, identity_name="Apple Development: Fixture (EXAMPLE123)", distribution=True)
        profile["ProvisionsAllDevices"] = False
        with self.assertRaises(signing.SigningError):
            self.validate(profile, distribution=True)

    def testIdentityResolutionRequiresExactUniqueValidIdentity(self):
        result = type("Result", (), {"stdout": f'  1) {self.fingerprint} "{self.identity}"\n     1 valid identities found\n'})()
        with patch.object(signing.subprocess, "run", return_value=result):
            self.assertEqual(signing.resolve_identity(self.fingerprint), (self.fingerprint, self.identity))
            self.assertEqual(signing.resolve_identity(self.identity), (self.fingerprint, self.identity))
            for requested in ("-", "", "Developer ID", "0" * 40):
                with self.subTest(requested=requested), self.assertRaises(signing.SigningError):
                    signing.resolve_identity(requested)

    def testAllMetadataVariablesExpandAndProviderClassMatchesModule(self):
        root = Path(__file__).resolve().parent.parent
        replacements = {"$(TeamIdentifier)": self.team, "$(NetworkExtensionCapability)": signing.SYSTEM_CAPABILITY}
        for name in ("App.entitlements", "Proxy.entitlements", "ProxyInfo.plist"):
            template = plistlib.loads((root / "Support/Protection" / name).read_bytes())
            expanded = signing.substitute(template, replacements)
            self.assertNotIn(b"$(", plistlib.dumps(expanded))
        proxy = signing.substitute(plistlib.loads((root / "Support/Protection/ProxyInfo.plist").read_bytes()), replacements)
        self.assertEqual(proxy["CFBundlePackageType"], "SYSX")
        self.assertEqual(proxy["NetworkExtension"]["NEProviderClasses"]["com.apple.networkextension.app-proxy"],
                         "ArmourProxyExtension.ArmourProxyProvider")

    def testPublishingReplacesSeparateBundleAndRejectsSymlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            staging = dist / ".protected-build.fixture"
            staging.mkdir()
            source = staging / "Russian Armour Protected.app"
            source.mkdir()
            (source / "new").write_text("new")
            destination = dist / source.name
            destination.mkdir()
            (destination / "old").write_text("old")
            args = type("Args", (), {"source": str(source), "destination": str(destination)})()
            signing.publish(args)
            self.assertEqual((destination / "new").read_text(), "new")
            self.assertFalse((destination / "old").exists())
            source.mkdir()
            target = dist / "elsewhere"
            target.mkdir()
            link = dist / "linked.app"
            link.symlink_to(target, target_is_directory=True)
            args.destination = str(link)
            with self.assertRaises(signing.SigningError):
                signing.publish(args)


class CMSVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="armour-profile-tests-")
        cls.folder = Path(cls.temporary.name)
        cls.verifier = cls.folder / "verify-profile"
        subprocess.run(["/usr/bin/xcrun", "swiftc", str(Path(__file__).with_name("verify-provisioning-profile.swift")),
                        "-o", str(cls.verifier)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def assertRejected(self, encoded):
        result = subprocess.run([str(self.verifier)], input=encoded, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def testRejectsEmptyMalformedAndUnsignedPlist(self):
        for fixture in [b"", b"not cms", plistlib.dumps({"Fixture": True})]:
            with self.subTest(length=len(fixture)):
                self.assertRejected(fixture)

    def testRejectsUntrustedAndTamperedCMSSignatures(self):
        key, certificate = self.folder / "fixture.key", self.folder / "fixture.crt"
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=Untrusted Fixture", "-keyout", str(key), "-out", str(certificate)],
                       check=True, capture_output=True)
        payload = plistlib.dumps({"Fixture": True})
        encoded = subprocess.run(["/usr/bin/openssl", "smime", "-sign", "-binary", "-nodetach", "-signer", str(certificate),
                                  "-inkey", str(key), "-outform", "DER"], input=payload,
                                 check=True, capture_output=True).stdout
        self.assertRejected(encoded)
        self.assertIn(b"Fixture", encoded)
        self.assertRejected(encoded.replace(b"Fixture", b"Changed", 1))


if __name__ == "__main__":
    unittest.main()
