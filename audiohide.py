#!/usr/bin/env python3

import argparse
import binascii
import contextlib
import math
import os
import struct
import sys
import wave
from hashlib import sha256

import audioread
import taglib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter

SALT_BYTES = 8
KEY_BYTES = 32
ACCEPTED_FORMATS = [".mp3", ".flac", ".ogg"]


def decode(filename):
    """
    Convert input file to WAV
    :param filename: WAV file
    """
    filename = os.path.abspath(os.path.expanduser(filename))
    if not os.path.exists(filename):
        print("File not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with audioread.audio_open(filename) as f:
            print('Input file: %i channels at %i Hz; %.1f seconds.' %
                  (f.channels, f.samplerate, f.duration),
                  file=sys.stderr)
            print('Backend:', str(type(f).__module__).split('.')[1],
                  file=sys.stderr)

            output_filename = filename + '.wav'
            with contextlib.closing(wave.open(output_filename, 'w')) as of:
                of.setnchannels(f.channels)
                of.setframerate(f.samplerate)
                of.setsampwidth(2)
                for buf in f:
                    of.writeframes(buf)
    except audioread.DecodeError:
        print("File could not be decoded.", file=sys.stderr)
        sys.exit(1)
    return output_filename


def encrypt(password, bytes):
    """
    Encrypt bytes using AES 256 in CTR mode

    :param password: password to derive key from using PBKDF2
    :param bytes: bytes to encrypt
    """
    rand = Random.new()
    salt = rand.read(SALT_BYTES)
    key = PBKDF2(password, salt, KEY_BYTES)
    iv = rand.read(AES.block_size)
    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return salt, iv, aes.encrypt(bytes)


def decrypt(password, iv, salt, bytes):
    """
    Decrypt bytes using AES 256 in CTR mode

    :param password: password to derive key from using PBKDF2
    :param iv: initialization vector
    :param salt: salt used with PBKDF2 for key derivation
    :param bytes: bytes to decrypt
    """
    key = PBKDF2(password, salt, KEY_BYTES)
    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.decrypt(bytes)


def steg(carrier_file, file_to_hide, password, output_file):
    """
    Steg file into WAV via LSB

    :param carrier_file: WAV file to hold stegged data
    :param file_to_hide: file to hide in WAV
    :param password: password for encryption
    :param output_file: output file
    """
    with wave.open(carrier_file, 'r') as wav_file:
        params = wav_file.getparams()
        num_channels = wav_file.getnchannels()
        sample_width = wav_file.getsampwidth()
        num_frames = wav_file.getnframes()
        num_samples = num_frames * num_channels

        with open(file_to_hide, "rb") as hidden_file:
            data = hidden_file.read()
            # We can hide up to num_lsb bits in each sample of the sound file
            filesize = len(data)
            num_lsb = math.ceil(filesize * 8 / num_samples)
            if num_lsb > 4:
                raise ValueError("Input file too large to hide, max byte to hide is {}"
                                 .format((num_samples * num_lsb) // 8))

            # Create hash for original data
            hash = sha256()
            hash.update(data)
            digest = hash.digest()
            # Encrypt data using passphrase
            salt, iv, encrypted = encrypt(password, data)

            if sample_width == 1:  # samples are unsigned 8-bit integers
                fmt = "{}B".format(num_samples)
                mask = (1 << 8) - (1 << num_lsb)
                # Don't skip any samples for 8 bit depth wav files
                min_sample = -(1 << 8)
            elif sample_width == 2:  # samples are signed 16-bit integers
                fmt = "{}h".format(num_samples)
                mask = (1 << 15) - (1 << num_lsb)
                min_sample = -(1 << 15)
            else:
                raise ValueError("File has an unsupported bit-depth")

            raw_data = list(struct.unpack(fmt, wav_file.readframes(num_frames)))

        # The number of bits we've processed from the input file
        data_index = 0
        sound_index = 0

        # values will hold the altered sound data
        values = []
        buffer = 0
        buffer_length = 0
        done = False

        while not done:
            while buffer_length < num_lsb and (data_index // 8) < len(encrypted):
                # If we don't have enough data in the buffer, add the rest of the next byte from the file to it.
                buffer += (encrypted[data_index // 8] >> (data_index % 8)) << buffer_length
                bits_added = 8 - (data_index % 8)
                buffer_length += bits_added
                data_index += bits_added

            # Retrieve the next num_lsb bits from the buffer for use later
            current_data = buffer % (1 << num_lsb)
            buffer >>= num_lsb
            buffer_length -= num_lsb

            while (sound_index < len(raw_data) and
                   raw_data[sound_index] == min_sample):
                # If the next sample from the sound file is the smallest possible
                # value, we skip it. Changing the LSB of such a value could cause
                # an overflow and drastically change the sample in the output.
                values.append(struct.pack(fmt[-1], raw_data[sound_index]))
                sound_index += 1

            if sound_index < len(raw_data):
                current_sample = raw_data[sound_index]
                sound_index += 1

                sign = 1
                if current_sample < 0:
                    # We alter the LSBs of the absolute value of the sample to
                    # avoid problems with two's complement. This also avoids
                    # changing a sample to the smallest possible value, which we
                    # would skip when attempting to recover data.
                    current_sample = -current_sample
                    sign = -1

                altered_sample = sign * ((current_sample & mask) | current_data)
                values.append(struct.pack(fmt[-1], altered_sample))

            if data_index // 8 >= len(encrypted) and buffer_length <= 0:
                done = True

        while sound_index < len(raw_data):
            # Write the rest of the samples to file
            values.append(struct.pack(fmt[-1], raw_data[sound_index]))
            sound_index += 1

        # Write stegged file
        stegged = wave.open(output_file, "w")
        stegged.setparams(params)
        stegged.setnchannels(num_channels)
        stegged.setnframes(num_frames)
        stegged.writeframes(b"".join(values))
        stegged.close()

        # Write metadata to stegged file
        output_song = taglib.File(output_file)
        output_song.tags["SIZE"] = str(filesize)
        output_song.tags["SHA256"] = binascii.hexlify(digest)
        output_song.tags["LSB"] = str(num_lsb)
        output_song.tags["SALT"] = binascii.hexlify(salt)
        output_song.tags["IV"] = binascii.hexlify(iv)
        output_song.tags["EMBEDDED_NAME"] = os.path.basename(file_to_hide)
        output_song.save()

        # Cleanup
        os.remove(carrier_file)


def unsteg(audio_file, password):
    """
    Unsteg file from WAV
    :param audio_file: stegged WAV file
    :param password: password for encryption
    """
    input_song = taglib.File(audio_file)
    if not int(input_song.tags["LSB"][0]):
        raise ValueError("No file is hidden inside")

    file_name = input_song.tags["EMBEDDED_NAME"][0]
    bytes_to_recover = int(input_song.tags["SIZE"][0])
    content_sha256 = binascii.unhexlify(input_song.tags["SHA256"][0])
    num_lsb = int(input_song.tags["LSB"][0])
    iv = binascii.unhexlify(input_song.tags["IV"][0])
    salt = binascii.unhexlify(input_song.tags["SALT"][0])

    input_song.save()

    sound = wave.open(audio_file, "r")

    num_channels = sound.getnchannels()
    sample_width = sound.getsampwidth()
    num_frames = sound.getnframes()
    num_samples = num_frames * num_channels

    if sample_width == 1:  # samples are unsigned 8-bit integers
        fmt = "{}B".format(num_samples)
        # Don't skip any samples for 8 bit depth wav files
        min_sample = -(1 << 8)
    elif sample_width == 2:  # samples are signed 16-bit integers
        fmt = "{}h".format(num_samples)
        min_sample = -(1 << 15)
    else:
        raise ValueError("File has an unsupported bit-depth")

    # Put all the samples from the sound file into a list
    raw_data = list(struct.unpack(fmt, sound.readframes(num_frames)))
    # Used to extract the least significant num_lsb bits of an integer
    mask = (1 << num_lsb) - 1
    output_file = open(file_name, "wb+")

    data = bytearray()
    sound_index = 0
    buffer = 0
    buffer_length = 0

    while bytes_to_recover > 0:
        next_sample = raw_data[sound_index]
        if next_sample != min_sample:
            # Since we skipped samples with the minimum possible value when
            # hiding data, we do the same here.
            buffer += (abs(next_sample) & mask) << buffer_length
            buffer_length += num_lsb
        sound_index += 1

        while buffer_length >= 8 and bytes_to_recover > 0:
            # If we have more than a byte in the buffer, add it to data
            # and decrement the number of bytes left to recover.
            current_data = buffer % (1 << 8)
            buffer >>= 8
            buffer_length -= 8
            data += struct.pack('1B', current_data)
            bytes_to_recover -= 1

    data = decrypt(password, iv, salt, bytes(data))

    # Hash data and verify
    hash = sha256()
    hash.update(data)
    digest = hash.digest()
    if not (digest == content_sha256):
        raise ValueError("Wrong passphrase")

    output_file.write(data)
    output_file.close()
    print("Saved '%s'." % file_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hide file in audio file")
    parser.add_argument("-s", "--steg", help="carrier audio file to steg")
    parser.add_argument("-i", "--input-file", help="file to hide")
    parser.add_argument("-o", "--output-file", help="output file")
    parser.add_argument("-u", "--unsteg", help="unsteg image")
    parser.add_argument("-p", "--password", help="password for encrypted data", required=True)
    argparse_namespace = parser.parse_args()

    if argparse_namespace.steg and argparse_namespace.unsteg:
        parser.exit(-1, "ERROR: Can't steg and unsteg simultaneously")
    if argparse_namespace.steg:
        if not argparse_namespace.input_file:
            parser.exit(-1, "ERROR: Please set input file to hide in audio")
        else:
            if not os.path.isfile(argparse_namespace.steg):
                parser.exit(-1, "ERROR: file '{}' does not exist".format(argparse_namespace.steg))
            if not os.path.isfile(argparse_namespace.input_file):
                parser.exit(-1, "ERROR: file '{}' does not exist".format(argparse_namespace.input_file))
            _, extension = os.path.splitext(argparse_namespace.steg)
            if extension not in ACCEPTED_FORMATS:
                parser.exit(-1, "ERROR: '*{}' files not supported".format(extension))
            print("Decoding file to PCM...")
            wav_filename = decode(argparse_namespace.steg)
            print("Stegging '%s' into '%s'..." % (argparse_namespace.input_file, argparse_namespace.output_file))
            steg(wav_filename, argparse_namespace.input_file, argparse_namespace.password,
                 argparse_namespace.output_file)
    if argparse_namespace.unsteg:
        if not os.path.isfile(argparse_namespace.unsteg):
            parser.exit(-1, "ERROR: file '{}' does not exist".format(argparse_namespace.unsteg))
        print("Unstegging '%s'..." % argparse_namespace.unsteg)
        unsteg(argparse_namespace.unsteg, argparse_namespace.password)
