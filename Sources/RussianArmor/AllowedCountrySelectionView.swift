import SwiftUI

/// Keep first-run setup and Settings on the same check-and-confirm path.
struct AllowedCountrySelectionView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            switch model.externalCheck {
            case .observed(let observation):
                Text("Текущая страна VPN: \(observation.countryName) (\(observation.countryCode))")
                    .font(AppTypography.description)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Разрешить страну \(observation.countryCode)") {
                    model.trustCurrentCountry()
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isSleeping)
                .accessibilityIdentifier("protection-trust-country")
            case .checking:
                ProgressView("Проверяем IP и страну…")
                    .controlSize(.small)
            case .failed(let message):
                Text(message)
                    .font(AppTypography.description)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            case .notChecked, .needsRecheck:
                Text("Включите VPN, затем проверьте и разрешите текущую страну. До подтверждения Claude остаётся на паузе.")
                    .font(AppTypography.description)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if !model.externalCheck.isChecking {
                Button(checkTitle) { model.refreshExternalIP() }
                    .disabled(model.isSleeping)
                    .accessibilityIdentifier("protection-check-country")
            }
        }
    }

    private var checkTitle: String {
        if case .observed = model.externalCheck { return "Проверить заново" }
        return "Проверить IP и страну"
    }
}
