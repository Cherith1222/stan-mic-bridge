import AppKit

// Reproducible vector artwork. Run with an output directory ending in .iconset.
guard CommandLine.arguments.count == 2 else {
    fputs("Usage: GenerateIcon OUTPUT.iconset\n", stderr)
    exit(1)
}
let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

func render(pixels: Int) throws -> Data {
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels,
        pixelsHigh: pixels, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
        isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
        let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
        throw NSError(domain: "GenerateIcon", code: 1)
    }
    NSGraphicsContext.saveGraphicsState()
    defer { NSGraphicsContext.restoreGraphicsState() }
    NSGraphicsContext.current = context
    let cg = context.cgContext
    cg.setAllowsAntialiasing(true)
    cg.setShouldAntialias(true)
    cg.scaleBy(x: CGFloat(pixels) / 1024, y: CGFloat(pixels) / 1024)

    let tile = NSBezierPath(roundedRect: NSRect(x: 64, y: 64, width: 896, height: 896),
                            xRadius: 190, yRadius: 190)
    NSGradient(starting: NSColor(srgbRed: 0.07, green: 0.24, blue: 0.66, alpha: 1),
               ending: NSColor(srgbRed: 0.04, green: 0.69, blue: 0.72, alpha: 1))!
        .draw(in: tile, angle: 45)

    // A single bold microphone remains legible at menu and Finder thumbnail sizes.
    NSColor.white.setFill()
    NSBezierPath(roundedRect: NSRect(x: 412, y: 418, width: 200, height: 354),
                 xRadius: 100, yRadius: 100).fill()
    NSColor.white.setStroke()
    let cradle = NSBezierPath()
    cradle.lineWidth = 50
    cradle.lineCapStyle = .round
    cradle.move(to: NSPoint(x: 326, y: 550))
    cradle.line(to: NSPoint(x: 326, y: 478))
    cradle.curve(to: NSPoint(x: 698, y: 478),
                 controlPoint1: NSPoint(x: 326, y: 230),
                 controlPoint2: NSPoint(x: 698, y: 230))
    cradle.line(to: NSPoint(x: 698, y: 550))
    cradle.stroke()

    let stem = NSBezierPath()
    stem.lineWidth = 48
    stem.lineCapStyle = .round
    stem.move(to: NSPoint(x: 512, y: 292))
    stem.line(to: NSPoint(x: 512, y: 220))
    stem.stroke()

    // The microphone stand doubles as a bridge joining two endpoint dots.
    let bridge = NSBezierPath()
    bridge.lineWidth = 38
    bridge.lineCapStyle = .round
    bridge.move(to: NSPoint(x: 342, y: 210))
    bridge.curve(to: NSPoint(x: 682, y: 210),
                 controlPoint1: NSPoint(x: 425, y: 270),
                 controlPoint2: NSPoint(x: 599, y: 270))
    bridge.stroke()
    NSColor(srgbRed: 0.63, green: 1, blue: 0.91, alpha: 1).setFill()
    for x in [CGFloat(342), CGFloat(682)] {
        NSBezierPath(ovalIn: NSRect(x: x - 27, y: 183, width: 54, height: 54)).fill()
    }
    guard let png = bitmap.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "GenerateIcon", code: 2)
    }
    return png
}

for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let suffix = scale == 2 ? "@2x" : ""
        let name = "icon_\(size)x\(size)\(suffix).png"
        try render(pixels: size * scale).write(to: output.appendingPathComponent(name))
    }
}
print("Generated \(output.path)")
