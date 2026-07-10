//! Tray/window icon rendering. Reuses the globe glyph from the iOS app icon
//! (`../flextunnel-ios/icon.svg`, 1024 viewBox): crosshair lines, two inner
//! ellipses, and an outer circle, white on a blue gradient. macOS renders the
//! bare glyph as a template image — the OS adapts it to light/dark menu bars,
//! matching the iOS "tinted" appearance — with the connection state shown by
//! opacity plus a corner status badge when connected: a plain dot while some
//! profiles are still connecting, upgrading to a checkmark once every connecting
//! profile has connected successfully. The badge stays monochrome on macOS so
//! the icon remains a crisp template (a colored icon renders as a blurry
//! non-template image in the menu bar); on Windows it is green on the full-color
//! badge (grayscale while disconnected).

use tiny_skia::{
    BlendMode, Color, FillRule, GradientStop, LineCap, LineJoin, LinearGradient, Paint, PathBuilder,
    Pixmap, Point, PremultipliedColorU8, Rect, SpreadMode, Stroke, Transform,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrayState {
    Idle,
    Connecting,
    /// At least one profile is connected, but others are still connecting or
    /// reconnecting — rendered with a plain status dot.
    Connected,
    /// Every profile that was connecting has connected successfully (none still
    /// in progress) — rendered with a status checkmark instead of the dot.
    AllConnected,
    Reconnecting,
    Failed,
}

// Geometry from icon.svg, in its 1024x1024 viewBox.
const VIEWBOX_CENTER: f32 = 512.0;
const R_OUTER: f32 = 337.92;
const R_INNER: f32 = 168.96;
const LINE_HALF: f32 = 337.92; // the crosshair lines span 174.08..849.92
const STROKE_THIN: f32 = 32.768;
const STROKE_OUTER: f32 = 51.2;
/// Glyph extent from the center: outer circle radius plus half its stroke.
const GLYPH_EXTENT: f32 = R_OUTER + STROKE_OUTER / 2.0;
/// Ratio of the glyph extent to the icon's half-size in the source icon, so the
/// badge keeps the same glyph-to-background proportions as the iOS icon.
const BADGE_GLYPH_FILL: f32 = GLYPH_EXTENT / VIEWBOX_CENTER;

/// Maps viewBox coordinates into pixel space (uniform scale about the center).
struct Mapper {
    k: f32,
    off: f32,
}

impl Mapper {
    fn map(&self, v: f32) -> f32 {
        (v - VIEWBOX_CENTER) * self.k + self.off
    }

    fn scale(&self, v: f32) -> f32 {
        v * self.k
    }
}

fn round_stroke(width: f32) -> Stroke {
    Stroke {
        width,
        line_cap: LineCap::Round,
        ..Stroke::default()
    }
}

/// Stroke the globe glyph into `pixmap`, scaled so its extent reaches `fill`
/// (fraction of the half-size) from the center.
fn draw_glyph(pixmap: &mut Pixmap, paint: &Paint, fill: f32) {
    let half = pixmap.width() as f32 / 2.0;
    let m = Mapper {
        k: half * fill / GLYPH_EXTENT,
        off: half,
    };
    let c = half;
    let id = Transform::identity();

    let mut pb = PathBuilder::new();
    pb.move_to(c, m.map(VIEWBOX_CENTER - LINE_HALF));
    pb.line_to(c, m.map(VIEWBOX_CENTER + LINE_HALF));
    pb.move_to(m.map(VIEWBOX_CENTER - LINE_HALF), c);
    pb.line_to(m.map(VIEWBOX_CENTER + LINE_HALF), c);
    for (rx, ry) in [(R_INNER, R_OUTER), (R_OUTER, R_INNER)] {
        if let Some(rect) = Rect::from_ltrb(
            c - m.scale(rx),
            c - m.scale(ry),
            c + m.scale(rx),
            c + m.scale(ry),
        ) {
            pb.push_oval(rect);
        }
    }
    if let Some(path) = pb.finish() {
        pixmap.stroke_path(&path, paint, &round_stroke(m.scale(STROKE_THIN)), id, None);
    }

    let mut pb = PathBuilder::new();
    pb.push_circle(c, c, m.scale(R_OUTER));
    if let Some(path) = pb.finish() {
        pixmap.stroke_path(&path, paint, &round_stroke(m.scale(STROKE_OUTER)), id, None);
    }
}

/// Overlay a "connected" status badge: a filled dot in the bottom-right,
/// separated from the glyph behind it by a ring. `ring` is the ring's fill
/// color, or `None` to punch a transparent gap (used by the macOS template,
/// where only alpha matters). When `checkmark` is set, a check is stroked over
/// the dot in the ring's treatment (the ring color, or a transparent punch on
/// the template) to signal that every connecting profile has connected. Drawn
/// last, so it sits on top.
fn draw_status_dot(pixmap: &mut Pixmap, dot: Color, ring: Option<Color>, checkmark: bool) {
    let s = pixmap.width() as f32;
    let (cx, cy) = (s * 0.70, s * 0.70);
    let dot_r = s * 0.24;
    let ring_r = dot_r + s * 0.09;
    let id = Transform::identity();

    let mut ring_paint = Paint {
        anti_alias: true,
        ..Paint::default()
    };
    match ring {
        Some(color) => ring_paint.set_color(color),
        None => ring_paint.blend_mode = BlendMode::Clear,
    }
    let mut pb = PathBuilder::new();
    pb.push_circle(cx, cy, ring_r);
    if let Some(path) = pb.finish() {
        pixmap.fill_path(&path, &ring_paint, FillRule::Winding, id, None);
    }

    let mut dot_paint = Paint {
        anti_alias: true,
        ..Paint::default()
    };
    dot_paint.set_color(dot);
    let mut pb = PathBuilder::new();
    pb.push_circle(cx, cy, dot_r);
    if let Some(path) = pb.finish() {
        pixmap.fill_path(&path, &dot_paint, FillRule::Winding, id, None);
    }

    if checkmark {
        draw_checkmark(pixmap, cx, cy, dot_r, ring);
    }
}

/// Stroke a checkmark centered on the status dot at `(cx, cy)` with radius
/// `dot_r`. It contrasts against the dot the same way the ring does: the ring's
/// color on the full-color badge, or a transparent Clear punch on the macOS
/// template (so the check reads as a cut-out once the OS tints the mask).
fn draw_checkmark(pixmap: &mut Pixmap, cx: f32, cy: f32, dot_r: f32, ring: Option<Color>) {
    let mut check_paint = Paint {
        anti_alias: true,
        ..Paint::default()
    };
    match ring {
        Some(color) => check_paint.set_color(color),
        None => check_paint.blend_mode = BlendMode::Clear,
    }
    // A check: left arm down to the low vertex, then up to the long tip.
    let mut pb = PathBuilder::new();
    pb.move_to(cx - dot_r * 0.45, cy + dot_r * 0.02);
    pb.line_to(cx - dot_r * 0.10, cy + dot_r * 0.38);
    pb.line_to(cx + dot_r * 0.50, cy - dot_r * 0.40);
    if let Some(path) = pb.finish() {
        let stroke = Stroke {
            width: dot_r * 0.30,
            line_cap: LineCap::Round,
            line_join: LineJoin::Round,
            ..Stroke::default()
        };
        pixmap.stroke_path(&path, &check_paint, &stroke, Transform::identity(), None);
    }
}

/// The bare glyph in black at the given opacity — a macOS template image.
#[cfg(target_os = "macos")]
fn glyph_only(size: u32, alpha: f32) -> Pixmap {
    let mut pixmap = Pixmap::new(size, size).expect("pixmap");
    let mut paint = Paint {
        anti_alias: true,
        ..Paint::default()
    };
    paint.set_color(Color::from_rgba(0.0, 0.0, 0.0, alpha).expect("color"));
    draw_glyph(&mut pixmap, &paint, 0.98);
    pixmap
}

/// The full-color badge: circular gradient background + white glyph, with the
/// same proportions as the iOS icon. `blue` false renders the grayscale
/// (disconnected) variant; `alpha` dims the whole badge.
fn badge(size: u32, blue: bool, alpha: f32) -> Pixmap {
    let mut pixmap = Pixmap::new(size, size).expect("pixmap");
    let half = size as f32 / 2.0;

    // icon.svg gradient: rgb(16%,49%,96%) -> rgb(10%,30%,78%), top-left to
    // bottom-right.
    let (start, end) = if blue {
        (
            Color::from_rgba8(41, 125, 245, 255),
            Color::from_rgba8(26, 77, 199, 255),
        )
    } else {
        (
            Color::from_rgba8(125, 131, 142, 255),
            Color::from_rgba8(85, 91, 102, 255),
        )
    };
    let bg = Paint {
        anti_alias: true,
        shader: LinearGradient::new(
            Point::from_xy(0.0, 0.0),
            Point::from_xy(size as f32, size as f32),
            vec![GradientStop::new(0.0, start), GradientStop::new(1.0, end)],
            SpreadMode::Pad,
            Transform::identity(),
        )
        .expect("gradient"),
        ..Paint::default()
    };

    let mut pb = PathBuilder::new();
    pb.push_circle(half, half, half);
    pixmap.fill_path(
        &pb.finish().expect("circle path"),
        &bg,
        FillRule::Winding,
        Transform::identity(),
        None,
    );

    let mut glyph = Paint {
        anti_alias: true,
        ..Paint::default()
    };
    glyph.set_color(Color::from_rgba(1.0, 1.0, 1.0, 1.0).expect("color"));
    draw_glyph(&mut pixmap, &glyph, BADGE_GLYPH_FILL);

    if alpha < 1.0 {
        // Uniformly scaling premultiplied components preserves the r/g/b <= a
        // invariant (truncation is monotonic).
        for p in pixmap.pixels_mut() {
            *p = PremultipliedColorU8::from_rgba(
                (p.red() as f32 * alpha) as u8,
                (p.green() as f32 * alpha) as u8,
                (p.blue() as f32 * alpha) as u8,
                (p.alpha() as f32 * alpha) as u8,
            )
            .expect("premultiplied color");
        }
    }
    pixmap
}

fn to_rgba(pixmap: Pixmap) -> Vec<u8> {
    pixmap
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect()
}

/// Whether the tray icon should be flagged as a macOS template image.
pub fn is_template() -> bool {
    cfg!(target_os = "macos")
}

/// RGBA pixels for the tray icon in the given state.
pub fn tray_rgba(state: TrayState) -> (Vec<u8>, u32, u32) {
    #[cfg(target_os = "macos")]
    {
        // tray-icon scales the NSImage to 18pt itself; 44px stays crisp on retina.
        let alpha = match state {
            TrayState::Connected | TrayState::AllConnected => 1.0,
            TrayState::Connecting | TrayState::Reconnecting => 0.6,
            TrayState::Idle | TrayState::Failed => 0.35,
        };
        let mut pixmap = glyph_only(44, alpha);
        if matches!(state, TrayState::Connected | TrayState::AllConnected) {
            // Monochrome so the icon stays a crisp template; the transparent
            // ring/check reads as a gap once the OS tints the mask.
            draw_status_dot(
                &mut pixmap,
                Color::from_rgba8(0, 0, 0, 255),
                None,
                state == TrayState::AllConnected,
            );
        }
        (to_rgba(pixmap), 44, 44)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let (blue, alpha) = match state {
            TrayState::Connected | TrayState::AllConnected => (true, 1.0),
            TrayState::Connecting | TrayState::Reconnecting => (true, 0.6),
            TrayState::Idle | TrayState::Failed => (false, 1.0),
        };
        let mut pixmap = badge(32, blue, alpha);
        if matches!(state, TrayState::Connected | TrayState::AllConnected) {
            // Green dot with a white ring to stand out against the blue badge;
            // a white check on top once every connecting profile is connected.
            draw_status_dot(
                &mut pixmap,
                Color::from_rgba8(52, 199, 89, 255),
                Some(Color::from_rgba8(255, 255, 255, 255)),
                state == TrayState::AllConnected,
            );
        }
        (to_rgba(pixmap), 32, 32)
    }
}

/// RGBA pixels for the app window icon (the full-color badge).
pub fn window_icon_rgba(size: u32) -> (Vec<u8>, u32, u32) {
    (to_rgba(badge(size, true, 1.0)), size, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_icon_has_expected_dimensions_and_content() {
        let (rgba, w, h) = tray_rgba(TrayState::Connected);
        assert_eq!(rgba.len(), (w * h * 4) as usize);
        assert!(rgba.chunks(4).any(|px| px[3] > 0), "icon is fully transparent");
    }

    #[test]
    fn state_variants_differ() {
        let (connected, ..) = tray_rgba(TrayState::Connected);
        let (idle, ..) = tray_rgba(TrayState::Idle);
        assert_ne!(connected, idle);
    }

    #[test]
    fn all_connected_checkmark_differs_from_plain_dot() {
        // The checkmark badge must be visually distinct from the plain dot so
        // "all connected" reads differently from "partially connected".
        let (all_connected, ..) = tray_rgba(TrayState::AllConnected);
        let (connected, ..) = tray_rgba(TrayState::Connected);
        assert_ne!(all_connected, connected);
    }

    #[test]
    fn window_icon_matches_requested_size() {
        let (rgba, w, h) = window_icon_rgba(256);
        assert_eq!((w, h), (256, 256));
        assert_eq!(rgba.len(), 256 * 256 * 4);
        // Center pixel sits on the white glyph crosshair.
        let center = ((128 * 256 + 128) * 4) as usize;
        assert_eq!(rgba[center + 3], 255);
    }
}
