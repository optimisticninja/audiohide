# audiohide

`audiohide` is a CLI utility to hide files in audio files. Supports `flac`, `ogg`, and `mp3`, will output 
the stegged file as `wav`. Outputting as `wav` doesn't lose quality on recompressing lossy formats.

## How it Works

`audiohide` works by hiding the file to hide in the least significant bits of the raw PCM stream. It supports 8 and
16 bit-depths. Metadata is written to the tags (salt/IV for encryption, number of least significant bits/size for 
hidden file) and is retrieved during the unstegging process.

## Requirements

You'll need the audio metadata library and a backend for audioread, `ffmpeg` should do just fine for the backend.

`sudo apt install libtag1-dev`

Then install the python requirements:

`pip install -r requirements.txt`

## Usage

```
usage: audiohide.py [-h] [-s STEG] [-i INPUT_FILE] -o OUTPUT_FILE [-u UNSTEG] -p PASSWORD

Hide file in audio file

optional arguments:
  -h, --help            show this help message and exit
  -s STEG, --steg STEG  carrier audio file to steg
  -i INPUT_FILE, --input-file INPUT_FILE
                        file to hide
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output file
  -u UNSTEG, --unsteg UNSTEG
                        unsteg image
  -p PASSWORD, --password PASSWORD
                        password for encrypted data
```

## Examples

Look in `examples/` for stegged/unstegged files.

## License

None, steg some audio and send secure files to friends, re-use the code freely.
