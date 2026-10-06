# Platform compatibility

HAMPP only works on platforms that pass zero-width characters through unchanged.
No platform has been tested yet. Run `hampp probe generate`, post the output, copy the
text back from the platform into a file and run `hampp probe check --sent <file> --received <file>`.
Add a row with your result.

| Platform | Date tested | Result (survives / stripped / altered) | Tester |
|---|---|---|---|
