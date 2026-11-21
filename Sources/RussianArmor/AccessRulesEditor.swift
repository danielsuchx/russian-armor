import ArmorCore
import SwiftUI

private struct ProfileDraft: Identifiable {
    var id: UUID
    var name: String
    var separate: Bool
    var shared: AccessRulesDraft
    var desktop: AccessRulesDraft
    var code: AccessRulesDraft
    init(_ profile: AccessProfile) {
        id = profile.id; name = profile.name; separate = profile.separateApplications
        shared = .init(profile.sharedRules); desktop = .init(profile.desktopRules); code = .init(profile.codeRules)
    }
    func parsed() throws -> AccessProfile {
        try AccessProfile(id: id, name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                          sharedRules: shared.parsed(), separateApplications: separate,
                          desktopRules: desktop.parsed(), codeRules: code.parsed())
    }
}

struct AccessRulesEditor: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var profiles: [ProfileDraft]
    @State private var active: UUID
    @State private var error: String?

    init(configuration: AccessConfiguration) {
        _profiles = State(initialValue: configuration.profiles.map(ProfileDraft.init))
        _active = State(initialValue: configuration.activeProfileID)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Правила допуска Claude").font(.title2.bold())
            Text("Работает только явно разрешённое. Запреты важнее разрешений; страна И IP-ограничение должны совпасть. Неизвестный выход — пауза.")
                .font(AppTypography.description).foregroundStyle(.secondary)
            Picker("Активный профиль", selection: $active) {
                ForEach(profiles) { profile in Text(profile.name).tag(profile.id) }
            }
            Text("Профили выбираются вручную. Название «Дом» или знакомый Wi-Fi не являются проверкой сети и не отменяют проверок IP и маршрута.")
                .font(AppTypography.description).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach($profiles) { $profile in
                        GroupBox {
                            VStack(alignment: .leading, spacing: 10) {
                                TextField("Название профиля", text: $profile.name).textFieldStyle(.roundedBorder)
                                Toggle("Отдельные правила Desktop и Code", isOn: $profile.separate)
                                    .onChange(of: profile.separate) { separate in
                                        if separate {
                                            profile.desktop = profile.shared
                                            profile.code = profile.shared
                                        }
                                    }
                                if profile.separate {
                                    RulesFields(title: "Claude Desktop", draft: $profile.desktop)
                                    RulesFields(title: "Claude Code", draft: $profile.code)
                                } else {
                                    RulesFields(title: "Общие правила", draft: $profile.shared)
                                }
                                if profiles.count > 1 {
                                    Button("Удалить этот профиль", role: .destructive) {
                                        profiles.removeAll { $0.id == profile.id }
                                        if active == profile.id, let first = profiles.first { active = first.id }
                                    }
                                }
                            }.padding(6)
                        }
                    }
                    Button("Добавить профиль") {
                        profiles.append(ProfileDraft(AccessProfile(name: "Новый профиль")))
                    }.disabled(profiles.count >= 20)
                }
            }
            if let error { Text(error).font(AppTypography.description).foregroundStyle(.orange) }
            Text("Адреса, которые вы вводите в правила, сохраняются локально как настройки. Наблюдаемые IP и адреса соединений не записываются в историю.")
                .font(AppTypography.description).foregroundStyle(.secondary)
            HStack {
                Button("Отмена") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Сохранить и перепроверить") { save() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            }
        }.padding(22).frame(width: 600, height: 680)
    }

    private func save() {
        do {
            let configuration = try AccessConfiguration(profiles: profiles.map { try $0.parsed() }, activeProfileID: active)
            try model.saveAccessConfiguration(configuration)
            dismiss()
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? "Не удалось сохранить правила."
        }
    }
}

private struct RulesFields: View {
    @Environment(\.networkAddressesHidden) private var hideIP
    let title: String
    @Binding var draft: AccessRulesDraft
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            TextField("Разрешённые страны: NL, SE", text: $draft.countries).textFieldStyle(.roundedBorder)
                .accessibilityLabel("Разрешённые страны — \(title)")
            Text("Пустой список стран ничего не разрешает. При расхождении геобаз для разрешения используется ipwho.is; явный запрет второй страны сохраняется.")
                .font(AppTypography.description).foregroundStyle(.secondary)
            TextField("Запрещённые страны: например RU", text: $draft.deniedCountries).textFieldStyle(.roundedBorder)
                .accessibilityLabel("Запрещённые страны — \(title)")
            Text("Разрешённые IP / CIDR · необязательно").font(AppTypography.description)
            if hideIP {
                Text("Адреса скрыты. Для редактирования IP выключите «Скрывать IP» в основных настройках.")
                    .font(AppTypography.description).foregroundStyle(.secondary)
            } else {
                TextEditor(text: $draft.ips).font(AppTypography.description.monospaced()).frame(height: 55)
                    .border(.secondary.opacity(0.3)).accessibilityLabel("Разрешённые IP — \(title)")
                Text("Пусто — любой IP разрешённой страны. Примеры формата: 203.0.113.7, 203.0.113.0/24, 2001:db8::/32.")
                    .font(AppTypography.description).foregroundStyle(.secondary)
                Text("Запрещённые IP / CIDR · необязательно").font(AppTypography.description)
                TextEditor(text: $draft.deniedIPs).font(AppTypography.description.monospaced()).frame(height: 55)
                    .border(.secondary.opacity(0.3)).accessibilityLabel("Запрещённые IP — \(title)")
            }
        }
    }
}
