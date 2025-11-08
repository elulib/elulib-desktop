# elulib-desktop

## Installation

### Local

Clone repository and install dependencies:
```bash
git clone https://github.com/elulib/elulib-desktop.git
cd elulib-desktop

# Install Node.js dependencies
npm install

# Install Rust toolchain (if not already installed)
rustup default stable

# Add required Rust targets
rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin x86_64-apple-darwin
```

Start development server:
```bash
npm run tauri dev
```

### Building

#### Windows
```bash
npm run build:win
```

#### macOS (Apple Silicon)
```bash
npm run build:mac
```

#### macOS (Intel)
```bash
npm run build:mac-intel
```
