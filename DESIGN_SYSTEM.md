# DT4SMS Design System

## Overview
This document defines the design language and UI patterns for Discovery Tool for Splunk MCP Server (DT4SMS). These patterns ensure consistency, usability, and professional appearance across all user-facing features.

---

## Core Design Principles

1. **Clarity First** - Users should immediately understand what actions are available
2. **Visual Hierarchy** - Important actions should be visually prominent
3. **Feedback Always** - Every action should provide clear, immediate feedback
4. **Consistency** - Similar features should look and behave similarly
5. **Professional Polish** - Enterprise-grade appearance with smooth interactions

---

## Design Pattern: Saved Asset Management

### Use Cases
This pattern applies to any feature where users can:
- Save/store configurations, credentials, or assets
- View a list of saved items
- Load/apply a saved item
- Delete saved items

**Examples:**
- LLM Credentials Vault
- Saved Query Templates
- Configuration Packages
- Report Templates
- Custom Discovery Profiles
- Saved Dashboards

### Pattern Components

#### 1. Container Section
```html
<div class="bg-gradient-to-r from-purple-50 to-indigo-50 rounded-lg p-4 border border-purple-200">
```

**Properties:**
- Gradient background (purple-50 to indigo-50)
- Rounded corners (`rounded-lg`)
- Padding (`p-4`)
- Colored border matching the gradient theme
- Sets this section apart as special/important

#### 2. Section Header
```html
<div class="flex items-center justify-between mb-4">
    <div>
        <h4 class="text-base font-bold text-gray-900">
            <i class="fas fa-key mr-2 text-purple-600"></i>
            [Feature Name]
        </h4>
        <p class="text-xs text-gray-600 mt-1">
            [Brief description of what this manages]
        </p>
    </div>
    <button class="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium shadow-sm hover:shadow-md transition-all">
        <i class="fas fa-plus-circle mr-2"></i>[Action Text]
    </button>
</div>
```

**Key Elements:**
- **Icon** - Represents the feature (fa-key, fa-file, fa-package, etc.)
- **Title** - Bold, clear feature name
- **Subtitle** - Helpful context in gray text
- **Primary Action Button** - Purple gradient, prominent placement

#### 3. Item Cards
```html
<div class="group bg-white rounded-lg p-4 border-2 border-gray-200 hover:border-purple-400 hover:shadow-lg transition-all">
    <div class="flex items-start justify-between gap-4">
        <!-- Left: Item Details -->
        <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-2">
                <i class="[icon-class] text-[color] text-lg"></i>
                <h5 class="text-base font-bold text-gray-900 truncate">[Item Name]</h5>
            </div>
            <div class="text-sm text-gray-600 space-y-1.5 pl-1">
                <!-- Property rows with icons -->
                <div class="flex items-center gap-2">
                    <i class="fas fa-[icon] w-4 text-gray-400"></i>
                    <span><span class="font-semibold text-gray-700">[Label]:</span> [Value]</span>
                </div>
                <!-- Repeat for each property -->
            </div>
        </div>
        
        <!-- Right: Action Buttons -->
        <div class="flex flex-col gap-2 shrink-0">
            <button class="px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105">
                <i class="fas fa-download mr-2"></i>Load
            </button>
            <button class="px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105">
                <i class="fas fa-trash-alt mr-2"></i>Delete
            </button>
        </div>
    </div>
</div>
```

**Card Anatomy:**
- **2px border** for prominence
- **Hover effects** - Border color change + shadow
- **Left section** - Item name + properties with icons
- **Right section** - Action buttons (Load/Apply, Delete)
- **Property rows** - Icon + bold label + value
- **Truncation** - Long text truncates gracefully

#### 4. Action Buttons

##### Primary Load/Apply Button
```html
<button class="px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105">
    <i class="fas fa-download mr-2"></i>Load
</button>
```

**Properties:**
- Blue color scheme (trustworthy, non-destructive action)
- Scale transform on hover (1.05x)
- Shadow depth increases on hover
- Icon + text for clarity

##### Destructive Delete Button
```html
<button class="px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-lg text-sm font-semibold shadow-md hover:shadow-lg transition-all transform hover:scale-105">
    <i class="fas fa-trash-alt mr-2"></i>Delete
</button>
```

**Properties:**
- Red color scheme (danger, destructive action)
- Same hover behaviors as primary
- Always requires confirmation dialog

#### 5. Empty State
```html
<div class="text-center py-12">
    <i class="fas fa-inbox text-gray-300 text-5xl mb-4"></i>
    <p class="text-base font-semibold text-gray-600">No saved [items] yet</p>
    <p class="text-sm text-gray-500 mt-2">
        Click <strong>"[Action Button Text]"</strong> above to save your first [item type]
    </p>
</div>
```

**Properties:**
- Large icon (5xl) in light gray
- Clear message about empty state
- Helpful instruction pointing to action button
- Centered layout with generous padding

#### 6. Loading State
```html
<div class="text-center py-10">
    <i class="fas fa-spinner fa-spin text-purple-600 text-4xl mb-4"></i>
    <p class="text-base font-semibold text-gray-700">Loading [items]...</p>
    <p class="text-sm text-gray-500 mt-2">[Optional context]</p>
</div>
```

**Properties:**
- Spinning icon in brand color
- Clear loading message
- Optional context/details

#### 7. Error State
```html
<div class="text-center py-10">
    <i class="fas fa-exclamation-triangle text-red-400 text-4xl mb-4"></i>
    <p class="text-base font-semibold text-red-700">Failed to load [items]</p>
    <p class="text-sm text-gray-600 mt-2">[Error message]</p>
</div>
```

**Properties:**
- Warning icon in red
- Clear error message
- Technical details in gray

#### 8. Success Notifications (Toast)
```javascript
const successDiv = document.createElement('div');
successDiv.className = 'fixed top-6 right-6 bg-green-600 text-white px-6 py-4 rounded-xl shadow-2xl z-50 animate-bounce';
successDiv.innerHTML = `
    <div class="flex items-center gap-3">
        <i class="fas fa-check-circle text-2xl"></i>
        <div>
            <p class="font-bold text-base">[Action] Successful!</p>
            <p class="text-sm opacity-90">[Item name or details]</p>
        </div>
    </div>
`;
document.body.appendChild(successDiv);
setTimeout(() => {
    successDiv.style.animation = 'none';
    successDiv.style.opacity = '0';
    successDiv.style.transition = 'opacity 0.3s';
    setTimeout(() => successDiv.remove(), 300);
}, 2500);
```

**Properties:**
- Fixed position (top-right corner)
- Green for success, red for delete/destructive
- Bounce animation on appear
- Two-line format (action + details)
- Fade out after 2.5 seconds
- Auto-remove after animation

#### 9. Save/Create Modal Dialog
```html
<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
    <div class="bg-white rounded-xl shadow-2xl w-full max-w-md">
        <!-- Header -->
        <div class="bg-gradient-to-r from-purple-600 to-indigo-600 text-white px-6 py-4 rounded-t-xl">
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <i class="fas fa-save text-2xl"></i>
                    <h2 class="text-xl font-bold">[Modal Title]</h2>
                </div>
                <button class="text-white hover:text-gray-200 transition-colors">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
        </div>
        
        <!-- Content -->
        <div class="p-6">
            <p class="text-sm text-gray-600 mb-4">
                [Helpful description of what will be saved]
            </p>
            
            <!-- Input Field -->
            <div class="mb-6">
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    [Field Label] <span class="text-red-500">*</span>
                </label>
                <input
                    type="text"
                    placeholder="[Example text]"
                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                />
            </div>
            
            <!-- Preview Box -->
            <div class="bg-gray-50 rounded-lg p-4 mb-6 border border-gray-200">
                <h4 class="text-xs font-semibold text-gray-700 mb-2 uppercase tracking-wide">
                    Preview
                </h4>
                <div class="space-y-1 text-sm text-gray-600">
                    [Preview content]
                </div>
            </div>
            
            <!-- Actions -->
            <div class="flex gap-3">
                <button class="flex-1 px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-lg font-medium transition-colors">
                    Cancel
                </button>
                <button class="flex-1 px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 disabled:from-gray-400 disabled:to-gray-400 text-white rounded-lg font-medium transition-all shadow-md hover:shadow-lg disabled:cursor-not-allowed">
                    <i class="fas fa-save mr-2"></i>Save
                </button>
            </div>
        </div>
    </div>
</div>
```

**Modal Properties:**
- Full-screen overlay with 50% opacity black background
- Centered modal with max-width
- Gradient header matching brand colors
- Clear close button (X)
- Descriptive text explaining action
- Preview section showing what will be saved
- Two-button footer (Cancel + Save)
- Purple gradient on save button

---

## Modal Structure Requirements

### Critical: Proper Vertical Scrolling

**⚠️ IMPORTANT**: Modal scrolling issues are common and difficult to debug. Follow this exact structure for all modals with scrollable content.

#### The Working Pattern

Use this proven structure that handles vertical content properly:

```jsx
{/* Full-screen overlay */}
<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    {/* Modal container - CRITICAL: Use h-5/6 for height */}
    <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl h-5/6 flex flex-col">
        
        {/* Header - NO sticky positioning */}
        <div className="p-6 border-b border-gray-200 flex justify-between items-center">
            <h2 className="text-2xl font-bold text-gray-900">Modal Title</h2>
            <button onClick={onClose}>
                <i className="fas fa-times text-gray-400 hover:text-gray-600"></i>
            </button>
        </div>
        
        {/* Scrollable content area - CRITICAL: flex-1 comes BEFORE overflow-y-auto */}
        <div className="flex-1 overflow-y-auto p-6">
            {/* All your content goes here */}
            {/* This area will scroll when content exceeds available height */}
        </div>
        
        {/* Footer - NO special positioning needed */}
        <div className="p-6 border-t border-gray-200 bg-gray-50">
            <div className="flex gap-3 justify-end">
                <button className="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-lg">
                    Cancel
                </button>
                <button className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg">
                    Save
                </button>
            </div>
        </div>
    </div>
</div>
```

#### Key Implementation Rules

1. **Modal Container Height**: 
   - ✅ DO: Use `h-5/6` (83.33% of viewport height)
   - ❌ DON'T: Use `h-[80vh]`, `max-h-[90vh]`, or `max-h-[calc(100vh-4rem)]`
   - **Why**: Percentage-based Tailwind classes are more reliable than custom vh calculations

2. **Flex Layout**:
   - ✅ DO: Use `flex flex-col` on modal container
   - ✅ DO: Put `flex-1` BEFORE `overflow-y-auto` on content area
   - ❌ DON'T: Use nested flex containers or complex height calculations
   - **Why**: Flexbox with flex-1 properly distributes space between header, content, and footer

3. **Padding**:
   - ✅ DO: Use consistent `p-6` on header, content, and footer
   - ❌ DON'T: Use different padding values (px-6 py-4, etc.)
   - ❌ DON'T: Add padding to backdrop container
   - **Why**: Consistent padding prevents layout shifts and alignment issues

4. **Positioning**:
   - ✅ DO: Keep header and footer as simple divs
   - ❌ DON'T: Use `sticky top-0` or `sticky bottom-0`
   - ❌ DON'T: Use `absolute` or `fixed` positioning for header/footer
   - **Why**: Flexbox handles positioning automatically; sticky causes scrolling conflicts

5. **Overflow**:
   - ✅ DO: Apply `overflow-y-auto` ONLY to the content div
   - ❌ DON'T: Apply overflow to backdrop, modal container, or individual sections
   - **Why**: Only the content area should scroll; header and footer stay visible

#### Common Mistakes to Avoid

```jsx
{/* ❌ WRONG - Don't do this */}
<div className="fixed inset-0 p-4"> {/* No padding on backdrop */}
    <div className="max-h-[90vh]"> {/* Don't use custom vh */}
        <div className="sticky top-0"> {/* No sticky on header */}
        <div className="overflow-y-auto max-h-[calc(100vh-200px)]"> {/* Too complex */}
```

```jsx
{/* ✅ RIGHT - Simple and works */}
<div className="fixed inset-0 flex items-center justify-center"> {/* No padding */}
    <div className="h-5/6 flex flex-col"> {/* Simple percentage height */}
        <div className="p-6 border-b"> {/* Simple header */}
        <div className="flex-1 overflow-y-auto p-6"> {/* flex-1 first */}
```

#### Size Variations

For different modal sizes, adjust both width and height together:

```jsx
{/* Small modal (forms, confirmations) */}
<div className="max-w-md h-auto"> {/* Auto height for small content */}

{/* Medium modal (settings, most use cases) */}
<div className="max-w-2xl h-5/6"> {/* Standard scrollable modal */}

{/* Large modal (full features like chat, discovery) */}
<div className="max-w-4xl h-5/6"> {/* Wide modal, same height */}

{/* Extra large modal (complex interfaces) */}
<div className="max-w-6xl h-5/6"> {/* Very wide, same height */}
```

#### Testing Checklist

After implementing a modal with scrollable content, verify:

- [ ] Modal displays at correct height (not too tall, not too short)
- [ ] Header is fully visible at top
- [ ] Footer is fully visible at bottom
- [ ] Content area scrolls smoothly when content exceeds available space
- [ ] Scrollbar appears only in content area, not on entire modal
- [ ] Header stays visible when scrolling (doesn't scroll away)
- [ ] Footer stays visible when scrolling (doesn't scroll away)
- [ ] Modal works on different screen sizes
- [ ] No layout shifts when opening/closing modal
- [ ] Content doesn't overflow behind header or footer

---

## Color Palette

### Primary Actions
- **Purple-Indigo Gradient**: `from-purple-600 to-indigo-600`
  - Main brand color
  - Used for: Primary actions, feature headers, save buttons

### Secondary Actions
- **Blue**: `bg-blue-600` hover: `bg-blue-700`
  - Used for: Load/apply actions, non-destructive operations

### Destructive Actions
- **Red**: `bg-red-600` hover: `bg-red-700`
  - Used for: Delete, remove, destructive operations

### Success
- **Green**: `bg-green-600`
  - Used for: Success notifications, confirmations

### Neutral
- **Gray Scale**:
  - Headers: `text-gray-900` (nearly black)
  - Body text: `text-gray-700`
  - Secondary text: `text-gray-600`
  - Subtle text: `text-gray-500`
  - Borders: `border-gray-200`, `border-gray-300`
  - Backgrounds: `bg-gray-50`, `bg-gray-100`

---

## Typography Scale

- **Section Titles**: `text-base font-bold` (16px, bold)
- **Card Titles**: `text-base font-bold` (16px, bold)
- **Body Text**: `text-sm` (14px)
- **Labels**: `text-sm font-semibold` (14px, semi-bold)
- **Subtitle/Help**: `text-xs` (12px)
- **Code/Technical**: `font-mono text-xs`

---

## Spacing Scale

- **Section Padding**: `p-4` (1rem / 16px)
- **Card Padding**: `p-4` (1rem / 16px)
- **Button Padding**: `px-4 py-2` (horizontal 1rem, vertical 0.5rem)
- **Gap Between Elements**: `gap-2` (0.5rem) to `gap-4` (1rem)
- **Margin Bottom**: `mb-2` to `mb-4`

---

## Animation Guidelines

### Hover Effects
```css
transition-all /* Smooth transitions on all properties */
hover:scale-105 /* Slight scale up on hover */
hover:shadow-lg /* Shadow depth increases */
```

### Loading States
```css
fa-spin /* Spinning animation for spinners */
animate-bounce /* Bounce for success notifications */
```

### Fade Out
```javascript
element.style.opacity = '0';
element.style.transition = 'opacity 0.3s';
```

---

## Icon Usage

### Font Awesome Icons
- **Feature Headers**: `fas fa-key`, `fas fa-package`, `fas fa-file`, etc.
- **Actions**: 
  - Save: `fas fa-save`, `fas fa-plus-circle`
  - Load: `fas fa-download`, `fas fa-arrow-circle-down`
  - Delete: `fas fa-trash-alt`, `fas fa-times-circle`
- **States**:
  - Empty: `fas fa-inbox`
  - Loading: `fas fa-spinner fa-spin`
  - Error: `fas fa-exclamation-triangle`
  - Success: `fas fa-check-circle`
- **Properties**: `fas fa-cog`, `fas fa-brain`, `fas fa-link`, `fas fa-sliders-h`

### Icon Sizing
- **Headers**: `text-lg` to `text-2xl`
- **Cards**: `text-lg`
- **Empty States**: `text-4xl` to `text-5xl`
- **Buttons**: Default size with `mr-2` spacing

---

## Responsive Considerations

### Container Width
```css
max-w-md /* Modals: 28rem (448px) */
w-full /* Full width with max constraints */
```

### Scrollable Lists
```css
max-h-64 /* Maximum height before scroll */
overflow-y-auto /* Vertical scrolling */
```

### Mobile-First
- Use flexbox for layouts
- `flex-col` on mobile, `flex-row` on desktop when appropriate
- Touch-friendly button sizes (minimum `py-2`)

---

## Accessibility

### Button Requirements
- Clear text labels (not icon-only)
- `title` attribute for additional context
- Sufficient color contrast (white text on colored backgrounds)
- Hover states clearly visible

### Form Requirements
- Labels for all inputs
- Required field indicators (`<span class="text-red-500">*</span>`)
- Helpful placeholder text
- Focus rings on inputs (`focus:ring-2 focus:ring-purple-500`)

### Keyboard Navigation
- All interactive elements keyboard accessible
- Modal close on Escape key
- Form submit on Enter key

---

## Implementation Checklist

When implementing a new "saved assets" feature:

- [ ] Container with purple-indigo gradient background
- [ ] Section header with icon, title, subtitle
- [ ] Primary action button (Save/Add)
- [ ] Item cards with:
  - [ ] Hover effects (border + shadow)
  - [ ] Icon + bold title
  - [ ] Property rows with icons
  - [ ] Load button (blue)
  - [ ] Delete button (red)
- [ ] Empty state with helpful text
- [ ] Loading state with spinner
- [ ] Error state with clear message
- [ ] Success toast notifications
- [ ] Save modal dialog with:
  - [ ] Gradient header
  - [ ] Input validation
  - [ ] Preview section
  - [ ] Cancel + Save buttons
- [ ] Confirmation dialog for delete
- [ ] Smooth animations and transitions

---

## Code Examples

### React State Management
```javascript
const [savedItems, setSavedItems] = useState({});
const [isModalOpen, setIsModalOpen] = useState(false);
const [itemName, setItemName] = useState('');
```

### Loading Items
```javascript
const loadItems = async () => {
    try {
        const response = await fetch('/api/items');
        const items = await response.json();
        setSavedItems(items);
        // Update UI with items
    } catch (error) {
        // Show error state
    }
};
```

### HTML Generation (for innerHTML)
**Note**: Use `class` not `className` when generating HTML strings
```javascript
credList.innerHTML = Object.values(items).map(item => `
    <div class="bg-white rounded-lg p-4...">
        <!-- Use 'class' not 'className' -->
    </div>
`).join('');
```

---

## Future Enhancements

Potential improvements to this pattern:

1. **Bulk Operations** - Select multiple items for bulk delete
2. **Search/Filter** - Filter saved items by name or properties
3. **Sorting** - Sort by name, date created, last used
4. **Export/Import** - Share configurations between users
5. **Version History** - Track changes to saved items
6. **Duplicate/Clone** - Create copies of existing items
7. **Categories/Tags** - Organize items into groups
8. **Favorites** - Pin frequently used items to top

---

## Maintenance

### When to Update This Document

- New saved asset features are added
- User feedback suggests improvements
- Accessibility requirements change
- Brand colors or typography updated
- New animation patterns emerge

### Version History

- **v1.0** (2025-11-03) - Initial design system based on LLM Credentials Vault implementation
