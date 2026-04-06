import Foundation
import Vision
import ImageIO

func recognizeText(from path: String) throws {
    let url = URL(fileURLWithPath: path)
    guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
          let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
        throw NSError(domain: "OCR", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to load image: \(path)"])
    }

    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.recognitionLanguages = ["zh-Hans", "en-US"]
    request.usesLanguageCorrection = true

    let handler = VNImageRequestHandler(cgImage: image, options: [:])
    try handler.perform([request])

    print("=== \(path) ===")
    let observations = request.results ?? []
    for observation in observations {
        if let candidate = observation.topCandidates(1).first {
            print(candidate.string)
        }
    }
}

let paths = Array(CommandLine.arguments.dropFirst())
if paths.isEmpty {
    fputs("Usage: swift tmp_vision_ocr.swift <image>...\n", stderr)
    exit(1)
}

for path in paths {
    do {
        try recognizeText(from: path)
    } catch {
        fputs("Error: \(error)\n", stderr)
    }
}
