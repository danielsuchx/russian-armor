import Foundation

struct ReleaseVersion: Comparable, CustomStringConvertible, Sendable {
    private let parts: [Int]
    var description: String { parts.map(String.init).joined(separator: ".") }

    init?(_ value: String) {
        let fields = value.split(separator: ".", omittingEmptySubsequences: false)
        guard fields.count == 3 else { return nil }
        var parts: [Int] = []
        for field in fields {
            guard !field.isEmpty, field.count <= 9, field == "0" || field.first != "0",
                  field.utf8.allSatisfy({ (48...57).contains($0) }), let number = Int(field) else { return nil }
            parts.append(number)
        }
        self.parts = parts
    }

    static func < (lhs: Self, rhs: Self) -> Bool { lhs.parts.lexicographicallyPrecedes(rhs.parts) }
}

enum AppUpdateError: LocalizedError {
    case noRelease, invalidRelease, github(Int), invalidDownload, invalidBundle, incompatible, diskImage, destination, replaced, watchdog, signature

    var errorDescription: String? {
        switch self {
        case .noRelease: return "В GitHub Releases пока нет опубликованной версии."
        case .invalidRelease: return "В релизе GitHub отсутствует подходящий образ Russian Armor с контрольной суммой SHA-256."
        case .github(let status): return "GitHub вернул HTTP \(status). Повторите проверку позже."
        case .invalidDownload: return "Размер или контрольная сумма образа не совпали с данными GitHub. Скачайте обновление заново."
        case .invalidBundle: return "Проверка версии, идентификатора или подписи приложения завершилась ошибкой."
        case .incompatible: return "Эта версия не поддерживает архитектуру или версию macOS на вашем Mac."
        case .diskImage: return "Не удалось прочитать или извлечь образ обновления."
        case .destination: return "Не удалось заменить приложение. Перенесите его из образа диска в доступную для записи папку «Программы» и откройте оттуда."
        case .replaced: return "Установленная копия изменилась. Перезапустите Russian Armor перед обновлением."
        case .watchdog: return "Наблюдатель перезапуска недоступен. Повторите установку после перезапуска Russian Armor."
        case .signature: return "Подпись выпуска не прошла проверку. Установка отменена; защита остаётся включённой."
        }
    }
}

struct GitHubUpdate: Equatable, Sendable {
    let version: ReleaseVersion
    let url: URL
    let size: Int64
    let sha256: String
    var signatureURL: URL { url.appendingPathExtension("sig") }

    static let repository = "https://github.com/danielsuchx/russian-armor"
    static let latest = URL(string: "https://api.github.com/repos/danielsuchx/russian-armor/releases/latest")!
    private static let assetName = "Russian-Armor.dmg"

    private struct Release: Codable {
        let tag_name: String
        let draft, prerelease: Bool
        let assets: [Asset]
        struct Asset: Codable {
            let name: String
            let size: Int64
            let browser_download_url: String
            let digest: String?
        }
    }

    static func available(in data: Data, after current: ReleaseVersion, allowRollback: Bool = false) throws -> GitHubUpdate? {
        guard let release = try? JSONDecoder().decode(Release.self, from: data),
              !release.draft, !release.prerelease, release.tag_name.first == "v",
              let version = ReleaseVersion(String(release.tag_name.dropFirst())) else { throw AppUpdateError.invalidRelease }
        guard allowRollback ? version < current : version > current else { return nil }
        let matches = release.assets.filter { $0.name == assetName }
        let expected = "\(repository)/releases/download/\(release.tag_name)/\(assetName)"
        guard matches.count == 1, let asset = matches.first, asset.browser_download_url == expected,
              (1...209_715_200).contains(asset.size), let url = URL(string: expected),
              let digest = asset.digest, digest.hasPrefix("sha256:") else { throw AppUpdateError.invalidRelease }
        let hash = String(digest.dropFirst(7))
        guard hash.utf8.count == 64, hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw AppUpdateError.invalidRelease }
        return GitHubUpdate(version: version, url: url, size: asset.size, sha256: hash)
    }

    static func check(after current: ReleaseVersion, session: URLSession) async throws -> GitHubUpdate? {
        var request = URLRequest(url: latest)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Russian-Armor-Updater", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        if (response as? HTTPURLResponse)?.statusCode == 404 { throw AppUpdateError.noRelease }
        try validate(response)
        return try available(in: data, after: current)
    }

    static func rollbackVersions(in data: Data, before current: ReleaseVersion) throws -> [GitHubUpdate] {
        guard let releases = try? JSONDecoder().decode([Release].self, from: data) else { throw AppUpdateError.invalidRelease }
        let encoder = JSONEncoder()
        // Only signed, stable, canonical packages are eligible. Old unsigned
        // 0.2.x images are never offered as a shortcut around signature checks.
        return releases.compactMap { release -> GitHubUpdate? in
            guard !release.draft, !release.prerelease,
                  release.assets.contains(where: { $0.name == assetName + ".sig" && $0.size <= 256
                    && $0.browser_download_url == "\(repository)/releases/download/\(release.tag_name)/\(assetName).sig" }) else { return nil }
            // Round-trip the validated release shape through JSONSerialization;
            // its original fields are used by the same selection validator.
            guard let bytes = try? encoder.encode(release) else { return nil }
            return try? available(in: bytes, after: current, allowRollback: true)
        }.sorted { $0.version > $1.version }.prefix(8).map { $0 }
    }

    static func history(before current: ReleaseVersion, session: URLSession) async throws -> [GitHubUpdate] {
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/danielsuchx/russian-armor/releases?per_page=30")!)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Russian-Armor-Updater", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        try validate(response)
        guard data.count <= 2_097_152 else { throw AppUpdateError.invalidRelease }
        return try rollbackVersions(in: data, before: current)
    }

    static func validate(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse, let url = http.url, trusted(url) else { throw AppUpdateError.invalidRelease }
        guard http.statusCode == 200 else { throw AppUpdateError.github(http.statusCode) }
    }

    static func trusted(_ url: URL) -> Bool {
        let hosts = ["api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com"]
        return url.scheme == "https" && url.port == nil && url.user == nil && url.password == nil && hosts.contains(url.host ?? "")
    }
}

final class GitHubRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url.map(GitHubUpdate.trusted) == true ? request : nil)
    }
}
