# CA

## Dependencies

```bash
pacman -S libp11 opensc
```

## Usage

```bash
RUST_LOG=debug cargo run --release -- config.ron --exclude-tag lxd-2
```
