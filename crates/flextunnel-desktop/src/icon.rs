//! Tray/window icon rendering. Reuses the globe glyph from the iOS app icon
//! (`../flextunnel-ios/icon.svg`, 1024 viewBox): crosshair lines, two inner
//! ellipses, and an outer circle, white on a blue gradient. macOS renders the
//! bare glyph as a template image — the OS adapts it to light/dark menu bars,
//! matching the iOS "tinted" appearance — with the connection state shown by
//! opacity. Windows renders the full-color badge, grayscale while disconnected.

use tiny_skia::{
    Color, FillRule, GradientStop, LineCap, LinearGradient, Paint, PathBuilder, Pixmap, Point,
    PremultipliedColorU8, Rect, SpreadMode, Stroke, Transform,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrayState {
    Idle,
    Connecting,
    Connected,
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

/// The bare glyph in black at the given opacity — a macOS template image.
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
            TrayState::Connected => 1.0,
            TrayState::Connecting | TrayState::Reconnecting => 0.6,
            TrayState::Idle | TrayState::Failed => 0.35,
        };
        (to_rgba(glyph_only(44, alpha)), 44, 44)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let (blue, alpha) = match state {
            TrayState::Connected => (true, 1.0),
            TrayState::Connecting | TrayState::Reconnecting => (true, 0.6),
            TrayState::Idle | TrayState::Failed => (false, 1.0),
        };
        (to_rgba(badge(32, blue, alpha)), 32, 32)
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
    fn window_icon_matches_requested_size() {
        let (rgba, w, h) = window_icon_rgba(256);
        assert_eq!((w, h), (256, 256));
        assert_eq!(rgba.len(), 256 * 256 * 4);
        // Center pixel sits on the white glyph crosshair.
        let center = ((128 * 256 + 128) * 4) as usize;
        assert_eq!(rgba[center + 3], 255);
    }
}
