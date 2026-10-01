import SwiftUI

/// The Void-Which-Binds visual language: **dark-first, teal accent**, monospace for key
/// material. One place for the colors, fonts, and the reusable card / button /
/// pill treatments every screen shares, so the eight screens read as one app.
enum VB {

    // MARK: - Palette (dark-first)

    /// Near-black page background.
    static let bg = Color(hex: 0x0B0F0E)
    /// Slightly raised surface for cards.
    static let surface = Color(hex: 0x151C1B)
    /// A second, lighter surface for nested rows / inputs.
    static let surface2 = Color(hex: 0x1E2726)
    /// Hairline separators / card borders.
    static let hairline = Color(hex: 0x2A3735)

    /// The teal brand accent.
    static let teal = Color(hex: 0x2ED4BA)
    /// A dimmer teal for fills / glows.
    static let tealDim = Color(hex: 0x1B7A6C)

    static let textPrimary = Color(hex: 0xF2F7F6)
    static let textSecondary = Color(hex: 0x9BB0AC)
    static let textFaint = Color(hex: 0x64756F)

    static let danger = Color(hex: 0xFF6B6B)
    static let warn = Color(hex: 0xF2C14E)
    static let good = teal

    // MARK: - Fonts

    static func mono(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
    static func rounded(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .rounded)
    }
}

// MARK: - Reusable treatments

/// The standard raised card: padded, rounded, hairline-bordered surface.
struct VBCard: ViewModifier {
    var padding: CGFloat = 18
    func body(content: Content) -> some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(VB.surface, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(VB.hairline, lineWidth: 1)
            )
    }
}

extension View {
    func vbCard(padding: CGFloat = 18) -> some View { modifier(VBCard(padding: padding)) }

    /// Apply the app's dark background to a full screen.
    func vbScreen() -> some View {
        self.frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(VB.bg.ignoresSafeArea())
            .foregroundStyle(VB.textPrimary)
    }
}

/// The primary teal action button.
struct VBPrimaryButtonStyle: ButtonStyle {
    var enabled: Bool = true
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(VB.rounded(17, .semibold))
            .foregroundStyle(Color(hex: 0x04110F))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(enabled ? VB.teal : VB.tealDim.opacity(0.5),
                        in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .opacity(configuration.isPressed ? 0.85 : 1)
    }
}

/// A secondary, outlined button.
struct VBSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(VB.rounded(17, .medium))
            .foregroundStyle(VB.textPrimary)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(VB.surface2, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(VB.hairline, lineWidth: 1))
            .opacity(configuration.isPressed ? 0.85 : 1)
    }
}

/// A small status pill (e.g. "Secure Enclave", "Trusted").
struct VBPill: View {
    let text: String
    var systemImage: String? = nil
    var tint: Color = VB.teal
    var body: some View {
        HStack(spacing: 5) {
            if let systemImage { Image(systemName: systemImage).font(.system(size: 11, weight: .semibold)) }
            Text(text).font(VB.rounded(12, .semibold))
        }
        .foregroundStyle(tint)
        .padding(.horizontal, 10).padding(.vertical, 5)
        .background(tint.opacity(0.13), in: Capsule())
        .overlay(Capsule().strokeBorder(tint.opacity(0.35), lineWidth: 1))
    }
}

// MARK: - Color hex

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: alpha
        )
    }
}
