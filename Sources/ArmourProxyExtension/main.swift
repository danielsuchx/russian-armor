import Foundation
import NetworkExtension

// This executable is launched by macOS as a Network Extension system extension.
// Running the binary directly does not install or enable any network rules.
NEProvider.startSystemExtensionMode()
dispatchMain()
