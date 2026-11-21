import SwiftUI

private struct HiddenNetworkAddressesKey: EnvironmentKey { static let defaultValue = false }
extension EnvironmentValues {
    var networkAddressesHidden: Bool {
        get { self[HiddenNetworkAddressesKey.self] }
        set { self[HiddenNetworkAddressesKey.self] = newValue }
    }
}
struct NetworkPrivacyModifier: ViewModifier {
    @ObservedObject var engine: NetworkEngineStore
    func body(content: Content) -> some View { content.environment(\.networkAddressesHidden, engine.hideIP) }
}
