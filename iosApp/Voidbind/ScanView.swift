import AVFoundation
import SwiftUI
import VoidWhichBinds

/// The QR scanner. A scanned (or pasted) `void-which-binds:` code is classified by the KMP
/// `VoidbindQr.parse` and dispatched: a **login** QR opens the web-login approval
/// sheet, a **pair** invite opens the SAS-verify flow. The camera runs on device;
/// in the Simulator (no camera) it falls back to a manual-entry field so the
/// dispatch is still exercisable.
struct ScanView: View {
    let engine: VoidbindEngine
    /// The enrolled device cert, needed to approve a login. Nil during add-device onboarding.
    var cert: String? = nil
    /// The per-RP approval policy manager, threaded to the login-approval sheet so it can
    /// show/set the site's policy and record the decision. Nil during add-device onboarding.
    var policy: ApprovalPolicyManager? = nil
    var onLogin: (_ origin: String) -> Void = { _ in }

    @Environment(\.dismiss) private var dismiss
    @State private var manualEntry = ""
    @State private var error: String?
    @State private var dispatch: Dispatch?

    enum Dispatch: Identifiable {
        case login(String), pair(String)
        var id: String { switch self { case .login(let s): return "l:\(s)"; case .pair(let s): return "p:\(s)" } }
    }

    var body: some View {
        VStack(spacing: 0) {
            cameraArea
            manualArea
        }
        .vbScreen()
        .navigationTitle("Scan")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Close") { dismiss() }.foregroundStyle(VB.teal)
            }
        }
        .toolbarBackground(VB.bg, for: .navigationBar)
        .sheet(item: $dispatch) { d in
            NavigationStack {
                switch d {
                case .login(let uri):
                    WebLoginApprovalView(engine: engine, cert: cert ?? "", loginQr: uri, policy: policy) { origin in
                        onLogin(origin); dispatch = nil; dismiss()
                    }
                case .pair(let uri):
                    PairView(mode: .join, engine: engine, joinQr: uri)
                }
            }
        }
    }

    // MARK: - Camera (device) / placeholder (simulator)

    private var cameraArea: some View {
        ZStack {
            #if targetEnvironment(simulator)
            VB.surface
            VStack(spacing: 10) {
                Image(systemName: "camera.metering.unknown")
                    .font(.system(size: 40)).foregroundStyle(VB.textFaint)
                Text("Camera isn’t available in the Simulator")
                    .font(VB.rounded(14)).foregroundStyle(VB.textSecondary)
                Text("Paste a void-which-binds: code below to test the dispatch.")
                    .font(VB.rounded(12)).foregroundStyle(VB.textFaint)
            }
            #else
            QRScannerCamera { code in handle(code) }
            #endif

            // Reticle overlay.
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .strokeBorder(VB.teal, lineWidth: 3)
                .frame(width: 220, height: 220)
                .shadow(color: VB.teal.opacity(0.5), radius: 10)
        }
        .frame(maxWidth: .infinity)
        .frame(height: 380)
    }

    private var manualArea: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(VB.rounded(13)).foregroundStyle(VB.danger)
            }
            Text("Enter a code manually").font(VB.rounded(14, .semibold)).foregroundStyle(VB.textSecondary)
            HStack(spacing: 10) {
                TextField("", text: $manualEntry,
                          prompt: Text("void-which-binds:login?… / void-which-binds:pair?…").foregroundColor(VB.textFaint))
                    .font(VB.mono(13))
                    .autocorrectionDisabled().textInputAutocapitalization(.never)
                    .padding(12)
                    .background(VB.surface2, in: RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(VB.hairline, lineWidth: 1))
                Button { handle(manualEntry) } label: {
                    Image(systemName: "arrow.right.circle.fill").font(.system(size: 30))
                        .foregroundStyle(manualEntry.isEmpty ? VB.tealDim : VB.teal)
                }
                .disabled(manualEntry.isEmpty)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    private func handle(_ uri: String) {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        do {
            switch try engine.parseScanned(trimmed) {
            case is VoidbindQr.Login: error = nil; dispatch = .login(trimmed)
            case is VoidbindQr.Pair:  error = nil; dispatch = .pair(trimmed)
            default: error = "That isn’t a Void-Which-Binds code."
            }
        } catch {
            self.error = "That isn’t a Void-Which-Binds code."
        }
    }
}

// MARK: - AVFoundation camera (device only)

#if !targetEnvironment(simulator)
/// A live camera preview that reports the first `void-which-binds:` QR payload it reads.
struct QRScannerCamera: UIViewRepresentable {
    let onCode: (String) -> Void

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.configure(onCode: onCode)
        return view
    }
    func updateUIView(_ uiView: PreviewView, context: Context) {}

    final class PreviewView: UIView, AVCaptureMetadataOutputObjectsDelegate {
        private let session = AVCaptureSession()
        private var onCode: ((String) -> Void)?
        private var delivered = false

        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        private var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }

        func configure(onCode: @escaping (String) -> Void) {
            self.onCode = onCode
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input) else { return }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            previewLayer.session = session
            previewLayer.videoGravity = .resizeAspectFill
            DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput,
                            didOutput objects: [AVMetadataObject],
                            from connection: AVCaptureConnection) {
            guard !delivered,
                  let obj = objects.first as? AVMetadataMachineReadableCodeObject,
                  let value = obj.stringValue, value.hasPrefix("void-which-binds:") else { return }
            delivered = true
            onCode?(value)
        }
    }
}
#endif
