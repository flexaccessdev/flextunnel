//! The app's visual identity: design tokens plus style functions for every
//! widget, replacing iced's stock look. Everything keys off the system
//! light/dark mode (`Theme::extended_palette().is_dark`), so the stock
//! palette colors never show through.

use iced::overlay::menu;
use iced::widget::{button, checkbox, container, pick_list, text_input, toggler};
use iced::{border, Border, Color, Shadow, Theme, Vector};

/// Status colors, readable on both modes.
pub const GREEN: Color = rgb(0x34C264);
pub const AMBER: Color = rgb(0xE6A01E);
pub const RED: Color = rgb(0xE05252);
pub const GRAY: Color = rgb(0x8A93A0);

#[derive(Clone, Copy)]
pub struct Tokens {
    /// Window background.
    pub bg: Color,
    /// Cards and grouped content.
    pub surface: Color,
    /// Raised interactive surfaces: inputs, hovered ghost buttons.
    pub surface_hi: Color,
    /// Hairline borders.
    pub border: Color,
    pub text: Color,
    /// Secondary text: labels, routes, metadata.
    pub dim: Color,
    /// Tertiary text: placeholders, footnotes.
    pub faint: Color,
    pub accent: Color,
    /// Text on accent-filled surfaces.
    pub on_accent: Color,
}

const fn rgb(hex: u32) -> Color {
    Color {
        r: ((hex >> 16) & 0xff) as f32 / 255.0,
        g: ((hex >> 8) & 0xff) as f32 / 255.0,
        b: (hex & 0xff) as f32 / 255.0,
        a: 1.0,
    }
}

const DARK: Tokens = Tokens {
    bg: rgb(0x101318),
    surface: rgb(0x181C23),
    surface_hi: rgb(0x232934),
    border: rgb(0x2A3038),
    text: rgb(0xE8EAED),
    dim: rgb(0x9AA3AF),
    faint: rgb(0x687180),
    accent: rgb(0x6D70F6),
    on_accent: Color::WHITE,
};

const LIGHT: Tokens = Tokens {
    bg: rgb(0xF4F5F7),
    surface: Color::WHITE,
    surface_hi: rgb(0xEDEFF2),
    border: rgb(0xE0E3E8),
    text: rgb(0x20242C),
    dim: rgb(0x5B6470),
    faint: rgb(0x98A0AC),
    accent: rgb(0x4F46E5),
    on_accent: Color::WHITE,
};

pub fn tokens(theme: &Theme) -> Tokens {
    if theme.extended_palette().is_dark {
        DARK
    } else {
        LIGHT
    }
}

/// The daemon-level style: window background and default text color.
pub fn app(theme: &Theme) -> iced::theme::Style {
    let t = tokens(theme);
    iced::theme::Style {
        background_color: t.bg,
        text_color: t.text,
    }
}

fn mix(a: Color, b: Color, factor: f32) -> Color {
    Color {
        r: a.r + (b.r - a.r) * factor,
        g: a.g + (b.g - a.g) * factor,
        b: a.b + (b.b - a.b) * factor,
        a: a.a + (b.a - a.a) * factor,
    }
}

fn plain(background: Option<Color>, text_color: Color, radius: f32) -> button::Style {
    button::Style {
        background: background.map(Into::into),
        text_color,
        border: border::rounded(radius),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Filled accent button (Connect, Save).
pub fn primary(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    match status {
        button::Status::Active => plain(Some(t.accent), t.on_accent, 8.0),
        button::Status::Hovered => plain(Some(mix(t.accent, Color::WHITE, 0.12)), t.on_accent, 8.0),
        button::Status::Pressed => plain(Some(mix(t.accent, Color::BLACK, 0.12)), t.on_accent, 8.0),
        button::Status::Disabled => plain(
            Some(t.accent.scale_alpha(0.35)),
            t.on_accent.scale_alpha(0.6),
            8.0,
        ),
    }
}

/// Accent-tinted button (Add, selected tab).
pub fn tinted(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    match status {
        button::Status::Active => plain(Some(t.accent.scale_alpha(0.16)), t.accent, 8.0),
        button::Status::Hovered | button::Status::Pressed => {
            plain(Some(t.accent.scale_alpha(0.26)), t.accent, 8.0)
        }
        button::Status::Disabled => plain(Some(t.accent.scale_alpha(0.08)), t.faint, 8.0),
    }
}

/// Quiet button: dim text on nothing, surfacing on hover (Edit, copy, tabs).
pub fn ghost(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    match status {
        button::Status::Active => plain(None, t.dim, 6.0),
        button::Status::Hovered | button::Status::Pressed => {
            plain(Some(t.surface_hi), t.text, 6.0)
        }
        button::Status::Disabled => plain(None, t.faint, 6.0),
    }
}

/// Quiet destructive button (Delete).
pub fn ghost_danger(_theme: &Theme, status: button::Status) -> button::Style {
    match status {
        button::Status::Active => plain(None, RED.scale_alpha(0.8), 6.0),
        button::Status::Hovered | button::Status::Pressed => {
            plain(Some(RED.scale_alpha(0.12)), RED, 6.0)
        }
        button::Status::Disabled => plain(None, RED.scale_alpha(0.4), 6.0),
    }
}

/// Outlined neutral button (Disconnect, Cancel).
pub fn outlined(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    let mut style = match status {
        button::Status::Active => plain(Some(t.surface), t.text, 8.0),
        button::Status::Hovered | button::Status::Pressed => plain(Some(t.surface_hi), t.text, 8.0),
        button::Status::Disabled => plain(Some(t.surface), t.faint, 8.0),
    };
    style.border = Border {
        color: t.border,
        width: 1.0,
        radius: 8.0.into(),
    };
    style
}

/// The profile sidebar: a raised column visually split from the detail pane.
pub fn sidebar(theme: &Theme) -> container::Style {
    let t = tokens(theme);
    container::Style {
        background: Some(t.surface.into()),
        ..container::Style::default()
    }
}

/// One sidebar row (profile or Logs): accent-tinted when selected, quiet
/// otherwise.
pub fn sidebar_row(selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let t = tokens(theme);
        if selected {
            return plain(Some(t.accent.scale_alpha(0.16)), t.text, 8.0);
        }
        match status {
            button::Status::Hovered | button::Status::Pressed => {
                plain(Some(t.surface_hi), t.text, 8.0)
            }
            _ => plain(None, t.text, 8.0),
        }
    }
}

/// Card container: raised surface, hairline border, soft radius.
pub fn card(theme: &Theme) -> container::Style {
    let t = tokens(theme);
    container::Style {
        background: Some(t.surface.into()),
        border: Border {
            color: t.border,
            width: 1.0,
            radius: 10.0.into(),
        },
        shadow: Shadow {
            color: Color::BLACK.scale_alpha(if theme.extended_palette().is_dark {
                0.2
            } else {
                0.05
            }),
            offset: Vector::new(0.0, 1.0),
            blur_radius: 3.0,
        },
        ..container::Style::default()
    }
}

/// Tinted rounded pill badge.
pub fn pill(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_theme| container::Style {
        background: Some(color.scale_alpha(0.15).into()),
        border: border::rounded(999),
        ..container::Style::default()
    }
}

/// Tinted full-width banner with a hairline of the same hue.
pub fn banner(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_theme| container::Style {
        background: Some(color.scale_alpha(0.1).into()),
        border: Border {
            color: color.scale_alpha(0.4),
            width: 1.0,
            radius: 10.0.into(),
        },
        ..container::Style::default()
    }
}

/// Solid round status dot.
pub fn dot(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_theme| container::Style {
        background: Some(color.into()),
        border: border::rounded(999),
        ..container::Style::default()
    }
}

pub fn input(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let t = tokens(theme);
    let focused = matches!(status, text_input::Status::Focused { .. });
    text_input::Style {
        background: t.surface_hi.into(),
        border: Border {
            color: if focused { t.accent } else { t.border },
            width: 1.0,
            radius: 8.0.into(),
        },
        icon: t.dim,
        placeholder: t.faint,
        value: t.text,
        selection: t.accent.scale_alpha(0.35),
    }
}

/// Dropdown field (the Logs pane's profile filter), matching `input`.
pub fn picker(theme: &Theme, status: pick_list::Status) -> pick_list::Style {
    let t = tokens(theme);
    let open = matches!(status, pick_list::Status::Opened { .. });
    pick_list::Style {
        text_color: t.text,
        placeholder_color: t.faint,
        handle_color: t.dim,
        background: t.surface_hi.into(),
        border: Border {
            color: if open { t.accent } else { t.border },
            width: 1.0,
            radius: 8.0.into(),
        },
    }
}

/// The dropdown's overlay menu, matching the card surfaces.
pub fn picker_menu(theme: &Theme) -> menu::Style {
    let t = tokens(theme);
    menu::Style {
        background: t.surface.into(),
        border: Border {
            color: t.border,
            width: 1.0,
            radius: 8.0.into(),
        },
        text_color: t.text,
        selected_text_color: t.on_accent,
        selected_background: t.accent.into(),
        shadow: Shadow {
            color: Color::BLACK.scale_alpha(0.2),
            offset: Vector::new(0.0, 2.0),
            blur_radius: 6.0,
        },
    }
}

/// The per-forward enable switch, green when on (the app's "running" color).
pub fn switch(theme: &Theme, status: toggler::Status) -> toggler::Style {
    let t = tokens(theme);
    let on = matches!(
        status,
        toggler::Status::Active { is_toggled: true } | toggler::Status::Hovered { is_toggled: true }
    );
    toggler::Style {
        background: if on { GREEN.into() } else { t.surface_hi.into() },
        background_border_width: 1.0,
        background_border_color: if on { Color::TRANSPARENT } else { t.border },
        foreground: Color::WHITE.into(),
        foreground_border_width: 0.0,
        foreground_border_color: Color::TRANSPARENT,
        text_color: None,
        border_radius: None,
        padding_ratio: 0.14,
    }
}

pub fn check(theme: &Theme, status: checkbox::Status) -> checkbox::Style {
    let t = tokens(theme);
    let checked = match status {
        checkbox::Status::Active { is_checked }
        | checkbox::Status::Hovered { is_checked }
        | checkbox::Status::Disabled { is_checked } => is_checked,
    };
    checkbox::Style {
        background: if checked {
            t.accent.into()
        } else {
            t.surface_hi.into()
        },
        icon_color: t.on_accent,
        border: Border {
            color: if checked { t.accent } else { t.border },
            width: 1.0,
            radius: 5.0.into(),
        },
        text_color: Some(t.text),
    }
}

/// Secondary text: labels, routes, metadata.
pub fn dim_text(theme: &Theme) -> iced::widget::text::Style {
    iced::widget::text::Style {
        color: Some(tokens(theme).dim),
    }
}

/// Tertiary text: section labels, footnotes.
pub fn faint_text(theme: &Theme) -> iced::widget::text::Style {
    iced::widget::text::Style {
        color: Some(tokens(theme).faint),
    }
}
