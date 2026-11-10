// Builds only the Tailwind utilities the app uses. Every color reads its RGB channels from a
// CSS variable (--c-<family>-<shade>) that each theme defines in src/frontend_legacy_template.html,
// so switching data-theme recolors every utility without touching markup.
const path = require('path');

const COLOR_FAMILIES = [
    'slate', 'gray', 'red', 'orange', 'amber', 'yellow', 'green', 'emerald',
    'cyan', 'sky', 'blue', 'indigo', 'violet', 'purple', 'fuchsia', 'rose',
];
const COLOR_SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];

const themeColor = (name) => ({ opacityVariable, opacityValue }) => {
    if (opacityValue !== undefined) {
        return `rgba(var(--c-${name}), ${opacityValue})`;
    }
    if (opacityVariable !== undefined) {
        return `rgba(var(--c-${name}), var(${opacityVariable}, 1))`;
    }
    return `rgb(var(--c-${name}))`;
};

const colors = {
    transparent: 'transparent',
    current: 'currentColor',
    white: themeColor('white'),
    black: themeColor('black'),
};
for (const family of COLOR_FAMILIES) {
    colors[family] = Object.fromEntries(COLOR_SHADES.map((shade) => [shade, themeColor(`${family}-${shade}`)]));
}

module.exports = {
    mode: 'jit',
    purge: [path.join(__dirname, 'src', 'frontend_legacy_template.html')],
    darkMode: false,
    theme: {
        colors,
        extend: {
            // Markup uses tints such as bg-rose-950/35 that fall between Tailwind's default steps.
            opacity: Object.fromEntries(
                Array.from({ length: 101 }, (_, value) => [String(value), String(value / 100)]),
            ),
        },
    },
    variants: {},
    plugins: [],
};
