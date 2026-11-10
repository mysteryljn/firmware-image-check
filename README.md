# firmware-image-check

Offline CI review for Intel HEX and Motorola S-record firmware images. It validates record checksums, termination, address windows, sparse overlaps and entry points, then compares occupied flash blocks without treating holes as erased bytes. Reports are JSON, Markdown or self-contained HTML and return exit code 1 when a policy gate fails.

```powershell
python -m pip install "firmware-image-check @ git+https://github.com/mysteryljn/firmware-image-check.git"
python -m firmware_image_check demo --output report.html
python -m firmware_image_check check build/app.hex --allow 0x08000000:0x08100000 --require-entrypoint
python -m firmware_image_check compare old.hex new.hex --block-size 4096 --fail-on-change
```

The bundled fixture is synthetic and only demonstrates the report flow. The parser is format-focused and does not infer erased flash values, ARM Thumb entry masking, device geometry or programmer behavior. It intentionally rejects overlapping records, including identical overlaps. Release wheels are attached to GitHub releases; no PyPI publication is implied.

## Development

`python -m unittest discover -s tests -v` runs the offline suite. The GitHub Actions matrix builds a wheel and runs the installed demo from an unrelated directory.

## License

MIT.
