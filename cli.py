#!/usr/bin/env python3
"""
STEGOSAURUS WRECKS - Command Line Interface
🦕 The most epic steg tool of all time 🦕

Usage:
    steg encode -i image.png -t "secret message" -o output.png
    steg decode -i encoded.png
    steg analyze image.png
    steg inject --help
"""

import os
import sys
import time
import typer
from pathlib import Path
from typing import Optional, List, Tuple
from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.syntax import Syntax
from rich.text import Text
from rich.columns import Columns
from rich.live import Live
from rich.align import Align
from rich import box

from PIL import Image

# Import our modules
from img_core import (
    encode, decode, create_config, calculate_capacity, analyze_image,
    detect_encoding, CHANNEL_PRESETS, EncodingStrategy,
    dct_encode, dct_decode, dct_capacity, DCT_STRENGTHS,
)
try:
    from crypto import encrypt, decrypt, get_available_methods, crypto_status
except Exception:
    # Gracefully handle broken cryptography library (e.g., broken system install)
    encrypt = decrypt = None
    def get_available_methods(): return ["none", "xor"]
    def crypto_status(): return "⚠ crypto module unavailable (install cryptography package)"
from injector import (
    generate_injection_filename, get_template_names,
    get_jailbreak_template, get_jailbreak_names,
    zalgo_text, leetspeak
)
from ascii_art import (
    BANNER, BANNER_SMALL, STEGOSAURUS_ASCII_SIMPLE, STEGOSAURUS_SMALL,
    STATUS, FOOTER, TAGLINES, section_header, channel_bar, COLORS
)
from matryoshka_core import (
    MatryoshkaConfig, encode_nested, decode_nested, capacity_for,
    plan_nesting, is_image_data, DecodeLayer, LayerReport,
)

# Initialize
console = Console()
app = typer.Typer(
    name="steg",
    help="🦕 STEGOSAURUS WRECKS - Ultimate Steganography Suite",
    add_completion=False,
    rich_markup_mode="rich",
)


class ChannelPreset(str, Enum):
    """Channel preset options"""
    R = "R"
    G = "G"
    B = "B"
    A = "A"
    RG = "RG"
    RB = "RB"
    RA = "RA"
    GB = "GB"
    GA = "GA"
    BA = "BA"
    RGB = "RGB"
    RGA = "RGA"
    RBA = "RBA"
    GBA = "GBA"
    RGBA = "RGBA"


class Strategy(str, Enum):
    """Encoding strategy options"""
    interleaved = "interleaved"
    sequential = "sequential"
    spread = "spread"
    randomized = "randomized"


def print_banner(small: bool = False):
    """Print the epic banner"""
    if small:
        console.print(BANNER_SMALL)
    else:
        console.print(BANNER)
    console.print()


def print_stego():
    """Print the stegosaurus"""
    console.print(STEGOSAURUS_ASCII_SIMPLE)


def success(msg: str):
    console.print(f"{STATUS['success']} [green]{msg}[/green]")


def error(msg: str):
    console.print(f"{STATUS['error']} [red]{msg}[/red]")


def warning(msg: str):
    console.print(f"{STATUS['warning']} [yellow]{msg}[/yellow]")


def info(msg: str):
    console.print(f"{STATUS['info']} [cyan]{msg}[/cyan]")


# ============== MAIN COMMAND ==============

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    🦕 STEGOSAURUS WRECKS - Ultimate Steganography Suite

    Hide data in images using LSB steganography with style.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        print_stego()
        console.print(f"\n[dim]Run [green]steg --help[/green] for usage information[/dim]")
        console.print(FOOTER)


# ============== ENCODE COMMAND ==============

@app.command()
def encode_cmd(
    input_image: Path = typer.Option(..., "--input", "-i", help="Input carrier image"),
    output: Path = typer.Option(None, "--output", "-o", help="Output image path"),
    text: Optional[str] = typer.Option(None, "--text", "-t", help="Text to encode"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="File to encode"),
    channels: ChannelPreset = typer.Option(ChannelPreset.RGB, "--channels", "-c", help="Channel preset"),
    bits: int = typer.Option(1, "--bits", "-b", help="Bits per channel (1-8)", min=1, max=8),
    strategy: Strategy = typer.Option(Strategy.interleaved, "--strategy", "-s", help="Encoding strategy"),
    seed: Optional[int] = typer.Option(None, "--seed", help="Random seed (for randomized strategy)"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Encryption password"),
    no_compress: bool = typer.Option(False, "--no-compress", help="Disable compression"),
    inject_filename: bool = typer.Option(False, "--inject-name", "-j", help="Use injection filename"),
    template: Optional[str] = typer.Option(None, "--template", help="Jailbreak template to encode"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """
    🔐 Encode data into an image (v3.0 - with CRC32 checksum & auto-detection)

    Examples:
        steg encode -i photo.png -t "secret message" -o hidden.png
        steg encode -i photo.png -f secret.txt -c RGBA -b 2 -p mypassword
        steg encode -i photo.png --template pliny_classic -j
        steg encode -i photo.png -t "spread out" -s spread
        steg encode -i photo.png -t "random order" -s randomized --seed 12345
    """
    if not quiet:
        print_banner(small=True)

    # Validate input
    if not input_image.exists():
        error(f"Input image not found: {input_image}")
        raise typer.Exit(1)

    if not text and not file and not template:
        error("Must provide --text, --file, or --template")
        raise typer.Exit(1)

    # Load payload
    if template:
        payload = get_jailbreak_template(template).encode('utf-8')
        info(f"Using template: [cyan]{template}[/cyan]")
    elif file:
        if not file.exists():
            error(f"File not found: {file}")
            raise typer.Exit(1)
        payload = file.read_bytes()
        info(f"Loaded file: [cyan]{file}[/cyan] ({len(payload):,} bytes)")
    else:
        payload = text.encode('utf-8')

    # Generate output filename
    if output is None:
        if inject_filename:
            output = Path(generate_injection_filename("chatgpt_decoder", channels.value))
        else:
            output = Path(f"steg_{input_image.stem}.png")

    # Load image
    try:
        image = Image.open(input_image)
        info(f"Loaded image: [cyan]{input_image}[/cyan] ({image.width}x{image.height})")
    except Exception as e:
        error(f"Failed to load image: {e}")
        raise typer.Exit(1)

    # Create config
    config = create_config(
        channels=channels.value,
        bits=bits,
        compress=not no_compress,
        strategy=strategy.value,
        seed=seed,
    )

    # Show capacity
    capacity = calculate_capacity(image, config)
    if not quiet:
        console.print(Panel(
            f"[cyan]Capacity:[/cyan] {capacity['human']}\n"
            f"[cyan]Channels:[/cyan] {channel_bar(channels.value)}\n"
            f"[cyan]Bits/Channel:[/cyan] {bits}\n"
            f"[cyan]Strategy:[/cyan] {strategy.value}\n"
            f"[cyan]Payload:[/cyan] {len(payload):,} bytes",
            title="[green]Configuration[/green]",
            border_style="green",
        ))

    # Check capacity
    if len(payload) > capacity['usable_bytes']:
        error(f"Payload too large! {len(payload):,} bytes > {capacity['usable_bytes']:,} available")
        raise typer.Exit(1)

    # Encrypt if password provided
    if password:
        with console.status("[cyan]Encrypting payload...[/cyan]", spinner="dots"):
            payload = encrypt(payload, password)
        success("Payload encrypted")

    # Encode
    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[green]Encoding...[/green]"),
        BarColumn(complete_style="green", finished_style="bright_green"),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Encoding", total=100)

        try:
            for i in range(0, 100, 10):
                progress.update(task, completed=i)
                time.sleep(0.05)

            result = encode(image, payload, config, str(output))
            progress.update(task, completed=100)

        except Exception as e:
            error(f"Encoding failed: {e}")
            raise typer.Exit(1)

    # Success output
    console.print()
    success(f"Data encoded successfully!")

    result_panel = Panel(
        f"[green]Output:[/green] {output}\n"
        f"[green]Size:[/green] {output.stat().st_size:,} bytes\n"
        f"[green]Payload:[/green] {len(payload):,} bytes\n"
        f"[green]Encrypted:[/green] {'Yes' if password else 'No'}",
        title=f"{STATUS['dino']} [green]Encoding Complete[/green]",
        border_style="green",
        box=box.DOUBLE,
    )
    console.print(result_panel)

    if not quiet:
        console.print(f"\n{FOOTER}")


# ============== DECODE COMMAND ==============

@app.command()
def decode_cmd(
    input_image: Path = typer.Option(..., "--input", "-i", help="Encoded image to decode"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file for binary data"),
    auto_detect: bool = typer.Option(True, "--auto/--no-auto", "-a", help="Auto-detect encoding config from header"),
    channels: ChannelPreset = typer.Option(ChannelPreset.RGB, "--channels", "-c", help="Channel preset (if not auto)"),
    bits: int = typer.Option(1, "--bits", "-b", help="Bits per channel (if not auto)", min=1, max=8),
    strategy: Strategy = typer.Option(Strategy.interleaved, "--strategy", "-s", help="Strategy (if not auto)"),
    seed: Optional[int] = typer.Option(None, "--seed", help="Random seed (if not auto)"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Decryption password"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip CRC32 checksum verification"),
    raw: bool = typer.Option(False, "--raw", help="Output raw bytes (hex)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """
    🔓 Decode data from an image (v3.0 - with auto-detection & checksum verification)

    Examples:
        steg decode -i hidden.png                     # Auto-detect config
        steg decode -i hidden.png --no-auto -c RGBA   # Manual config
        steg decode -i hidden.png -p mypassword       # With decryption
        steg decode -i hidden.png -o extracted.bin    # Save to file
    """
    if not quiet:
        print_banner(small=True)

    if not input_image.exists():
        error(f"Image not found: {input_image}")
        raise typer.Exit(1)

    # Load image
    try:
        image = Image.open(input_image)
        info(f"Loaded image: [cyan]{input_image}[/cyan] ({image.width}x{image.height})")
    except Exception as e:
        error(f"Failed to load image: {e}")
        raise typer.Exit(1)

    # Auto-detect or use manual config
    config = None
    if auto_detect:
        info("Auto-detecting encoding configuration...")
        detection = detect_encoding(image)
        if detection:
            success(f"Detected STEG v3 encoding!")
            if not quiet:
                console.print(Panel(
                    f"[cyan]Channels:[/cyan] {', '.join(detection['config']['channels'])}\n"
                    f"[cyan]Bits/Channel:[/cyan] {detection['config']['bits_per_channel']}\n"
                    f"[cyan]Strategy:[/cyan] {detection['config']['strategy']}\n"
                    f"[cyan]Compressed:[/cyan] {detection['config']['compression']}\n"
                    f"[cyan]Payload Size:[/cyan] {detection['payload_length']:,} bytes\n"
                    f"[cyan]Original Size:[/cyan] {detection['original_length']:,} bytes",
                    title="[green]Detected Configuration[/green]",
                    border_style="green",
                ))
            # Use None to let decode() use header config
            config = None
        else:
            warning("No STEG header detected, using manual config")
            config = create_config(
                channels=channels.value,
                bits=bits,
                strategy=strategy.value,
                seed=seed,
            )
    else:
        config = create_config(
            channels=channels.value,
            bits=bits,
            strategy=strategy.value,
            seed=seed,
        )
        if not quiet:
            console.print(Panel(
                f"[cyan]Channels:[/cyan] {channel_bar(channels.value)}\n"
                f"[cyan]Bits/Channel:[/cyan] {bits}\n"
                f"[cyan]Strategy:[/cyan] {strategy.value}",
                title="[cyan]Manual Configuration[/cyan]",
                border_style="cyan",
            ))

    # Decode
    with console.status("[cyan]Decoding...[/cyan]", spinner="dots"):
        try:
            data = decode(image, config, verify_checksum=not no_verify)
        except Exception as e:
            error(f"Decoding failed: {e}")
            raise typer.Exit(1)

    # Decrypt if password
    if password:
        with console.status("[cyan]Decrypting...[/cyan]", spinner="dots"):
            try:
                data = decrypt(data, password)
                success("Data decrypted")
            except Exception as e:
                error(f"Decryption failed: {e}")
                raise typer.Exit(1)

    success(f"Extracted {len(data):,} bytes")

    # Output
    if output:
        output.write_bytes(data)
        success(f"Saved to: {output}")
    elif raw:
        console.print(Panel(
            data.hex(),
            title="[cyan]Raw Data (hex)[/cyan]",
            border_style="cyan",
        ))
    else:
        # Try to decode as text
        try:
            text_data = data.decode('utf-8')
            console.print(Panel(
                text_data,
                title=f"{STATUS['decode']} [cyan]Decoded Message[/cyan]",
                border_style="cyan",
                box=box.DOUBLE,
            ))
        except UnicodeDecodeError:
            warning("Data is not valid UTF-8, showing hex preview:")
            console.print(Panel(
                data[:500].hex() + ("..." if len(data) > 500 else ""),
                title="[yellow]Binary Data (hex preview)[/yellow]",
                border_style="yellow",
            ))

    if not quiet:
        console.print(f"\n{FOOTER}")


# ============== ANALYZE COMMAND ==============

@app.command()
def analyze(
    input_image: Path = typer.Argument(..., help="Image to analyze"),
    full: bool = typer.Option(False, "--full", "-f", help="Full analysis with all channels"),
    recursive: bool = typer.Option(False, "--recursive", "-r", "--matryoshka",
                                   help="Recursively scan for Matryoshka nested stego"),
):
    """
    🔍 Analyze an image for steganographic content

    Examples:
        steg analyze photo.png
        steg analyze suspicious.png --full
    """
    print_banner(small=True)

    if not input_image.exists():
        error(f"Image not found: {input_image}")
        raise typer.Exit(1)

    try:
        image = Image.open(input_image)
    except Exception as e:
        error(f"Failed to load image: {e}")
        raise typer.Exit(1)

    with console.status("[cyan]Analyzing image...[/cyan]", spinner="dots"):
        analysis = analyze_image(image)

    # Image info
    info_table = Table(show_header=False, box=box.SIMPLE)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="white")
    info_table.add_row("File", str(input_image))
    info_table.add_row("Dimensions", f"{analysis['dimensions']['width']} x {analysis['dimensions']['height']}")
    info_table.add_row("Total Pixels", f"{analysis['total_pixels']:,}")
    info_table.add_row("Mode", analysis['mode'])
    info_table.add_row("Format", str(analysis['format']))

    console.print(Panel(info_table, title="[green]Image Information[/green]", border_style="green"))

    # Channel analysis
    channel_table = Table(box=box.ROUNDED)
    channel_table.add_column("Channel", style="bold")
    channel_table.add_column("Mean", justify="right")
    channel_table.add_column("Std Dev", justify="right")
    channel_table.add_column("LSB 0s", justify="right")
    channel_table.add_column("LSB 1s", justify="right")
    channel_table.add_column("Anomaly", justify="center")

    for ch_name, ch_data in analysis['channels'].items():
        lsb = ch_data['lsb_ratio']
        indicator = ch_data['chi_square_indicator']

        if indicator < 0.1:
            anomaly = "[green]✓ Normal[/green]"
        elif indicator < 0.3:
            anomaly = "[yellow]⚠ Slight[/yellow]"
        else:
            anomaly = "[red]⚠ HIGH[/red]"

        color = {"R": "red", "G": "green", "B": "blue", "A": "white"}[ch_name]
        channel_table.add_row(
            f"[{color}]█ {ch_name}[/{color}]",
            f"{ch_data['mean']:.1f}",
            f"{ch_data['std']:.1f}",
            f"{lsb['zeros']*100:.1f}%",
            f"{lsb['ones']*100:.1f}%",
            anomaly,
        )

    console.print(Panel(channel_table, title="[cyan]Channel Analysis[/cyan]", border_style="cyan"))

    # Capacity table
    cap_table = Table(box=box.SIMPLE)
    cap_table.add_column("Config", style="cyan")
    cap_table.add_column("Capacity", style="green", justify="right")

    for config_name, capacity in analysis['capacity_by_config'].items():
        cap_table.add_row(config_name, capacity)

    console.print(Panel(cap_table, title="[magenta]Capacity Estimates[/magenta]", border_style="magenta"))

    # Verdict
    max_indicator = max(
        ch['chi_square_indicator']
        for ch in analysis['channels'].values()
    )

    if max_indicator > 0.3:
        verdict = Panel(
            "[red bold]⚠ HIGH PROBABILITY OF HIDDEN DATA ⚠[/red bold]\n\n"
            "LSB distribution shows significant anomaly.\n"
            "This image likely contains steganographic content.",
            title="[red]Verdict[/red]",
            border_style="red",
            box=box.DOUBLE,
        )
    elif max_indicator > 0.1:
        verdict = Panel(
            "[yellow]⚠ Possible hidden data[/yellow]\n\n"
            "LSB distribution shows slight anomaly.\n"
            "Could be natural variation or light steganography.",
            title="[yellow]Verdict[/yellow]",
            border_style="yellow",
        )
    else:
        verdict = Panel(
            "[green]✓ No obvious steganographic indicators[/green]\n\n"
            "LSB distribution appears natural.\n"
            "Does not mean data isn't hidden - could use encryption or advanced techniques.",
            title="[green]Verdict[/green]",
            border_style="green",
        )

    console.print(verdict)

    # Recursive / Matryoshka scan
    if recursive:
        console.print()
        _run_recursive_scan(input_image)

    console.print(f"\n{FOOTER}")


def _run_recursive_scan(image_path: Path):
    """Run smart_scan_recursive on an image and print results."""
    try:
        from analysis_tools import smart_scan_recursive
    except ImportError:
        warning("analysis_tools.smart_scan_recursive not available")
        return

    with console.status("[magenta]🪆 Recursive Matryoshka scan...[/magenta]", spinner="dots"):
        result = smart_scan_recursive(image_path.read_bytes())

    if result.get("error"):
        warning(f"Recursive scan failed: {result['error']}")
        return

    if not result.get("is_matryoshka"):
        info("🪆 No nested stego layers detected")
        return

    depth = result["nested_depth"]
    count = result["layers_found"]

    table = Table(
        title=f"🪆 Matryoshka Scan — {count} layers, max depth {depth}",
        box=box.ROUNDED,
    )
    table.add_column("Depth", style="cyan", justify="right")
    table.add_column("Type", style="magenta")
    table.add_column("Size", style="green", justify="right")
    table.add_column("Preview", style="white")

    for layer in result["layers"]:
        preview = layer["preview"][:80] if layer["preview"] else ""
        table.add_row(
            str(layer["depth"]),
            layer["type"],
            f"{layer['data_size']:,} B" if layer["data_size"] else "",
            preview,
        )

    console.print(table)


# ============== INJECT COMMAND ==============

inject_app = typer.Typer(help="💉 Prompt injection tools")
app.add_typer(inject_app, name="inject")


@inject_app.command("filename")
def inject_filename(
    template: str = typer.Option("chatgpt_decoder", "--template", "-t", help="Filename template"),
    channels: str = typer.Option("RGB", "--channels", "-c", help="Channel string"),
    count: int = typer.Option(1, "--count", "-n", help="Number of filenames to generate"),
):
    """
    Generate prompt injection filenames

    Templates: chatgpt_decoder, claude_decoder, gemini_decoder, universal_decoder,
               system_override, roleplay_trigger, dev_mode, subtle, custom
    """
    print_banner(small=True)
    console.print(section_header("Injection Filename Generator"))
    console.print()

    for i in range(count):
        filename = generate_injection_filename(template, channels)
        console.print(f"  [green]{filename}[/green]")

    console.print(f"\n{FOOTER}")


@inject_app.command("templates")
def inject_templates():
    """List available jailbreak templates"""
    print_banner(small=True)
    console.print(section_header("Jailbreak Templates"))
    console.print()

    for name in get_jailbreak_names():
        template = get_jailbreak_template(name)
        preview = template[:80].replace('\n', ' ') + "..." if len(template) > 80 else template.replace('\n', ' ')
        console.print(f"  [cyan]{name}[/cyan]")
        console.print(f"    [dim]{preview}[/dim]")
        console.print()

    console.print(f"\n{FOOTER}")


@inject_app.command("show")
def inject_show(template: str = typer.Argument(..., help="Template name")):
    """Show full content of a jailbreak template"""
    print_banner(small=True)

    content = get_jailbreak_template(template)
    if content:
        console.print(Panel(
            content,
            title=f"[cyan]{template}[/cyan]",
            border_style="cyan",
        ))
    else:
        error(f"Template not found: {template}")

    console.print(f"\n{FOOTER}")


@inject_app.command("zalgo")
def inject_zalgo(
    text: str = typer.Argument(..., help="Text to convert"),
    intensity: int = typer.Option(3, "--intensity", "-i", help="Zalgo intensity (1-5)"),
):
    """Convert text to Zalgo (glitchy) text"""
    result = zalgo_text(text, intensity)
    console.print(Panel(result, title="[magenta]Zalgo Text[/magenta]", border_style="magenta"))


@inject_app.command("leet")
def inject_leet(
    text: str = typer.Argument(..., help="Text to convert"),
    intensity: int = typer.Option(2, "--intensity", "-i", help="Leet intensity (1-3)"),
):
    """Convert text to leetspeak"""
    result = leetspeak(text, intensity)
    console.print(Panel(result, title="[green]Leetspeak[/green]", border_style="green"))


# ============== DCT COMMANDS ==============

class DctRobustness(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


dct_app = typer.Typer(help="🎛  DCT steganography: frequency-domain (JPEG-survivable)")
app.add_typer(dct_app, name="dct")


@dct_app.command("encode")
def dct_encode_cmd(
    input_image: Path = typer.Option(..., "--input", "-i", help="Input carrier image"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output PNG path"),
    text: Optional[str] = typer.Option(None, "--text", "-t", help="Text to encode"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="File to encode"),
    robustness: DctRobustness = typer.Option(DctRobustness.medium, "--robustness", "-r", help="low / medium / high"),
    block_size: int = typer.Option(8, "--block-size", help="DCT block size (default 8)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """🎛  Embed data via DCT (survives JPEG-style recompression at medium/high)."""
    if not quiet:
        print_banner(small=True)
    if not input_image.exists():
        error(f"Input image not found: {input_image}")
        raise typer.Exit(1)
    if not text and not file:
        error("Must provide --text or --file")
        raise typer.Exit(1)

    payload = file.read_bytes() if file else text.encode("utf-8")
    if output is None:
        output = Path(f"steg_dct_{input_image.stem}.png")

    try:
        image = Image.open(input_image)
    except Exception as e:
        error(f"Failed to load image: {e}")
        raise typer.Exit(1)

    cap = dct_capacity(image, block_size=block_size)
    if not quiet:
        console.print(Panel(
            f"[cyan]Capacity:[/cyan] {cap['human']}\n"
            f"[cyan]Block size:[/cyan] {block_size}\n"
            f"[cyan]Robustness:[/cyan] {robustness.value} (strength={DCT_STRENGTHS[robustness.value]})\n"
            f"[cyan]Payload:[/cyan] {len(payload):,} bytes",
            title="[green]DCT Configuration[/green]",
            border_style="green",
        ))

    if len(payload) > cap["usable_bytes"]:
        error(f"Payload too large! {len(payload):,} bytes > {cap['usable_bytes']:,} available")
        raise typer.Exit(1)

    try:
        dct_encode(image, payload, robustness=robustness.value, block_size=block_size, output_path=str(output))
    except Exception as e:
        error(f"DCT encoding failed: {e}")
        raise typer.Exit(1)

    success(f"DCT-encoded {len(payload):,} bytes → {output}")
    if not quiet:
        console.print(f"\n{FOOTER}")


@dct_app.command("decode")
def dct_decode_cmd(
    input_image: Path = typer.Option(..., "--input", "-i", help="DCT-encoded image"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write recovered bytes here"),
    block_size: int = typer.Option(8, "--block-size", help="DCT block size (default 8)"),
    raw: bool = typer.Option(False, "--raw", help="Output raw bytes (hex)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """🔎 Recover a payload previously hidden with `steg dct encode`."""
    if not quiet:
        print_banner(small=True)
    if not input_image.exists():
        error(f"Image not found: {input_image}")
        raise typer.Exit(1)

    try:
        image = Image.open(input_image)
    except Exception as e:
        error(f"Failed to load image: {e}")
        raise typer.Exit(1)

    try:
        data = dct_decode(image, block_size=block_size)
    except Exception as e:
        error(f"DCT decoding failed: {e}")
        raise typer.Exit(1)

    success(f"Extracted {len(data):,} bytes via DCT")

    if output:
        output.write_bytes(data)
        success(f"Saved to: {output}")
    elif raw:
        console.print(Panel(data.hex(), title="[cyan]Raw Data (hex)[/cyan]", border_style="cyan"))
    else:
        try:
            console.print(Panel(data.decode("utf-8"), title=f"{STATUS['decode']} [cyan]Decoded Message[/cyan]",
                                border_style="cyan", box=box.DOUBLE))
        except UnicodeDecodeError:
            warning("Data is not valid UTF-8, showing hex preview:")
            console.print(Panel(data[:500].hex() + ("..." if len(data) > 500 else ""),
                                title="[yellow]Binary Data (hex preview)[/yellow]", border_style="yellow"))

    if not quiet:
        console.print(f"\n{FOOTER}")


@dct_app.command("capacity")
def dct_capacity_cmd(
    input_image: Path = typer.Option(..., "--input", "-i", help="Image to measure"),
    block_size: int = typer.Option(8, "--block-size", help="DCT block size (default 8)"),
):
    """📏 Report how many payload bytes fit under DCT."""
    if not input_image.exists():
        error(f"Image not found: {input_image}")
        raise typer.Exit(1)
    image = Image.open(input_image)
    cap = dct_capacity(image, block_size=block_size)
    table = Table(show_header=False, box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for k, v in cap.items():
        table.add_row(k, str(v))
    console.print(Panel(table, title="[cyan]DCT capacity[/cyan]", border_style="cyan"))


# ============== TEXT STEG COMMANDS ==============

import text_core

text_app = typer.Typer(help="🔤 Text steganography: hide/reveal in plain text")
app.add_typer(text_app, name="text")


def _read_cover_or_stego(path_or_dash: str) -> str:
    """Read UTF-8 text from a path, or from stdin if '-'."""
    if path_or_dash == "-":
        return sys.stdin.read()
    return Path(path_or_dash).read_text(encoding="utf-8")


@text_app.command("encode")
def text_encode_cmd(
    method: str = typer.Option(..., "--method", "-m", help=f"One of: {', '.join(text_core.METHODS)}"),
    cover: str = typer.Option(..., "--cover", "-c", help="Cover text file path (or '-' for stdin)"),
    secret: str = typer.Option(..., "--secret", "-s", help="Secret string to hide"),
    output: Optional[Path] = typer.Option(None, "--out", "-o", help="Output path (stdout if omitted)"),
):
    """Hide a secret string in a cover text via a classic text-steg method."""
    if method not in text_core.METHODS:
        error(f"unknown method '{method}'. Try one of: {', '.join(text_core.METHODS)}")
        raise typer.Exit(1)
    try:
        cover_text = _read_cover_or_stego(cover)
    except Exception as e:
        error(f"failed to read cover: {e}")
        raise typer.Exit(1)
    try:
        stego = text_core.encode(cover_text, secret, method)
    except text_core.TextStegCapacityError as e:
        error(str(e))
        raise typer.Exit(1)

    if output is None:
        sys.stdout.write(stego)
    else:
        output.write_text(stego, encoding="utf-8")
        success(f"wrote {len(stego)} chars ({len(stego.encode('utf-8'))} bytes) to {output}")


@text_app.command("decode")
def text_decode_cmd(
    method: str = typer.Option(..., "--method", "-m", help=f"One of: {', '.join(text_core.METHODS)}"),
    stego: str = typer.Option(..., "--stego", "-i", help="Stego text file path (or '-' for stdin)"),
):
    """Recover a hidden secret from a stego text."""
    if method not in text_core.METHODS:
        error(f"unknown method '{method}'. Try one of: {', '.join(text_core.METHODS)}")
        raise typer.Exit(1)
    try:
        stego_text = _read_cover_or_stego(stego)
    except Exception as e:
        error(f"failed to read stego: {e}")
        raise typer.Exit(1)
    recovered = text_core.decode(stego_text, method)
    sys.stdout.write(recovered)
    if recovered and not recovered.endswith("\n"):
        sys.stdout.write("\n")


@text_app.command("capacity")
def text_capacity_cmd(
    method: str = typer.Option(..., "--method", "-m", help=f"One of: {', '.join(text_core.METHODS)}"),
    cover: str = typer.Option(..., "--cover", "-c", help="Cover text file path (or '-' for stdin)"),
):
    """Report how many payload bytes a cover can carry under a method."""
    if method not in text_core.METHODS:
        error(f"unknown method '{method}'. Try one of: {', '.join(text_core.METHODS)}")
        raise typer.Exit(1)
    try:
        cover_text = _read_cover_or_stego(cover)
    except Exception as e:
        error(f"failed to read cover: {e}")
        raise typer.Exit(1)
    rep = text_core.capacity(cover_text, method)
    table = Table(show_header=False, box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for k, v in rep.items():
        table.add_row(k, str(v))
    console.print(Panel(table, title=f"[cyan]capacity: {method}[/cyan]", border_style="cyan"))


# ============== 🪆 MATRYOSHKA COMMANDS ==============

matryoshka_app = typer.Typer(
    name="matryoshka",
    help="🪆 Matryoshka nested-image steganography (Russian nesting dolls)",
    rich_markup_mode="rich",
)
app.add_typer(matryoshka_app)


def _load_carriers(paths: List[Path]) -> List[Tuple[Image.Image, str]]:
    """Load carrier images from paths. Returns innermost-first list."""
    carriers = []
    for p in paths:
        if not p.exists():
            error(f"Carrier image not found: {p}")
            raise typer.Exit(1)
        img = Image.open(p).convert("RGBA")
        carriers.append((img, p.name))
    # CLI accepts outermost-first; reverse to innermost-first
    carriers.reverse()
    return carriers


def _print_layer_tree(layers: List[DecodeLayer], indent: int = 0):
    """Pretty-print a nested decode layer tree."""
    prefix = "  " * indent
    for layer in layers:
        type_icon = {
            "steg_header": "📦",
            "nested_image": "🪆",
            "nested_image_raw": "🪆",
            "file": "📁",
            "text": "📝",
            "binary": "⚫",
            "no_data_found": "❌",
            "max_depth_reached": "⚠️",
            "error": "💥",
        }.get(layer.type, "❓")

        name_part = f" [{layer.filename}]" if layer.filename else ""
        size_part = f" ({layer.data_size:,} B)" if layer.data_size else ""
        print(f"{prefix}{type_icon} L{layer.depth} [{layer.type}]{name_part}{size_part}")
        if layer.preview and layer.type not in ("nested_image", "nested_image_raw"):
            preview_short = layer.preview[:120].replace("\n", " ")
            print(f"{prefix}   {preview_short}")
        if layer.nested:
            _print_layer_tree(layer.nested, indent + 1)


@matryoshka_app.command()
def encode(
    payload_path: Path = typer.Option(
        ..., "--payload", "-p", help="File to hide (innermost secret)"
    ),
    carriers: List[Path] = typer.Option(
        ..., "--carrier", "-c", help="Carrier image (outermost first; repeatable)"
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Output image path"
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-w", help="Encryption password (innermost layer only)"
    ),
    channels: str = typer.Option(
        "RGBA", "--channels", help="Channel preset (R, G, B, A, RGB, RGBA, etc.)"
    ),
    bits: int = typer.Option(
        2, "--bits", "-b", help="Bits per channel (1-8)", min=1, max=8
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print capacity plan only, do not encode"
    ),
):
    """
    🪆 Encode a payload into a stack of carrier images.

    Carriers are specified outermost-first (matching the mental model) and
    reversed internally to innermost-first for the encoding engine.

    Examples:
        stegg matryoshka encode -p secret.txt -c inner.png -c outer.png -o nested.png
        stegg matryoshka encode -p data.bin -c a.png -c b.png -c c.png --dry-run
    """
    if not carriers:
        error("At least one --carrier is required")
        raise typer.Exit(1)

    if not payload_path.exists():
        error(f"Payload file not found: {payload_path}")
        raise typer.Exit(1)

    payload = payload_path.read_bytes()
    info(f"Payload: {payload_path} ({len(payload):,} bytes)")

    carrier_tuples = _load_carriers(carriers)
    info(f"Carriers: {len(carrier_tuples)} layers (outermost-first on CLI)")

    config = MatryoshkaConfig(
        channels=channels, bits=bits, password=password,
        max_depth=max(len(carrier_tuples), 11),
    )

    if dry_run:
        info("Dry-run mode — capacity plan only")
        plan = plan_nesting(len(payload), carrier_tuples, config, mode="estimate")
        _print_plan(plan)
        return

    try:
        result_img, reports = encode_nested(payload, carrier_tuples, config)
    except ValueError as exc:
        error(str(exc))
        raise typer.Exit(1)

    if output is None:
        output = Path("matryoshka_encoded.png")

    result_img.save(output, format="PNG")
    success(f"Encoded {len(reports)} layers → {output}")
    _print_plan(reports)


def _print_plan(reports: List[LayerReport]):
    """Print a capacity plan / layer report table."""
    table = Table(title="🪆 Layer Plan", box=box.ROUNDED)
    table.add_column("Layer", style="cyan", justify="right")
    table.add_column("Carrier", style="magenta")
    table.add_column("Capacity", style="green", justify="right")
    table.add_column("Payload", style="yellow", justify="right")
    table.add_column("Fits", justify="center")
    table.add_column("Output", style="blue", justify="right")

    for r in reports:
        fits_icon = "✅" if r.fits else "❌"
        output_str = _format_size_cli(r.output_size) if isinstance(r.output_size, int) else str(r.output_size)
        table.add_row(
            str(r.layer),
            r.carrier_name,
            _format_size_cli(r.capacity),
            _format_size_cli(r.payload_size),
            fits_icon,
            output_str,
        )
    console.print(table)


def _format_size_cli(size_bytes: int | str) -> str:
    """Format bytes for CLI display."""
    if isinstance(size_bytes, str):
        return size_bytes
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


@matryoshka_app.command()
def decode(
    image: Path = typer.Argument(..., help="Image to recursively decode"),
    password: Optional[str] = typer.Option(
        None, "--password", "-w", help="Decryption password"
    ),
    max_depth: int = typer.Option(
        11, "--max-depth", "-d", help="Maximum recursion depth (1-11)", min=1, max=11
    ),
    extract_dir: Optional[Path] = typer.Option(
        None, "--extract-dir", "-e", help="Write each layer's raw data to files"
    ),
):
    """
    🪆 Recursively decode a Matryoshka-encoded image.

    Prints a depth-indented tree of discovered layers.  Use --extract-dir
    to write each layer's raw data to disk.

    Examples:
        stegg matryoshka decode nested.png
        stegg matryoshka decode nested.png -d 5 -e ./layers/
    """
    if not image.exists():
        error(f"Image not found: {image}")
        raise typer.Exit(1)

    img = Image.open(image).convert("RGBA")
    info(f"Decoding: {image} ({img.size[0]}x{img.size[1]})")

    config = MatryoshkaConfig(max_depth=max_depth, password=password)
    layers = decode_nested(img, config)

    if not layers:
        warning("No layers found")
        return

    print(f"\n🪆  Matryoshka decode — {image.name}")
    _print_layer_tree(layers)

    # Extract files if requested
    if extract_dir:
        extract_dir.mkdir(parents=True, exist_ok=True)
        _extract_layers(layers, extract_dir)


def _extract_layers(layers: List[DecodeLayer], out_dir: Path, prefix: str = ""):
    """Write DecodeLayer raw_data to disk."""
    for layer in layers:
        if layer.raw_data:
            name = layer.filename or f"layer{layer.depth}.bin"
            fname = f"{prefix}{name}"
            out_path = out_dir / fname
            out_path.write_bytes(layer.raw_data)
            info(f"  Extracted: {out_path}")
        if layer.nested:
            _extract_layers(layer.nested, out_dir, f"{prefix}L{layer.depth}_")


@matryoshka_app.command()
def plan(
    payload_size: int = typer.Argument(..., help="Size of innermost payload in bytes"),
    carriers: List[Path] = typer.Option(
        ..., "--carrier", "-c", help="Carrier image (outermost first; repeatable)"
    ),
    channels: str = typer.Option(
        "RGBA", "--channels", help="Channel preset"
    ),
    bits: int = typer.Option(
        2, "--bits", "-b", help="Bits per channel (1-8)", min=1, max=8
    ),
    exact: bool = typer.Option(
        False, "--exact", help="Actually encode to measure exact PNG sizes (slow)"
    ),
):
    """
    📐 Plan a Matryoshka nesting without encoding.

    Walks the carrier stack and predicts whether each layer has enough
    capacity for the expected payload (original data for innermost,
    serialised PNG for intermediate layers).

    Examples:
        stegg matryoshka plan 4096 -c a.png -c b.png -c c.png
        stegg matryoshka plan 1024 -c a.png -c b.png --exact
    """
    if not carriers:
        error("At least one --carrier is required")
        raise typer.Exit(1)

    carrier_tuples = _load_carriers(carriers)
    config = MatryoshkaConfig(channels=channels, bits=bits)

    mode = "exact" if exact else "estimate"
    info(f"Planning {len(carrier_tuples)} layers for {payload_size:,}B payload (mode={mode})")

    reports = plan_nesting(payload_size, carrier_tuples, config, mode=mode)
    _print_plan(reports)

    all_fit = all(r.fits for r in reports)
    if all_fit:
        success("All layers fit! ✓")
    else:
        first_bad = next(r for r in reports if not r.fits)
        error(f"Overflow at layer {first_bad.layer} ({first_bad.carrier_name}): "
              f"need {first_bad.payload_size:,}B, have {first_bad.capacity:,}B")


# ============== INFO COMMAND ==============

@app.command()
def info_cmd():
    """
    ℹ️ Show system information and capabilities
    """
    print_banner(small=True)
    print_stego()

    # Crypto status
    crypto = crypto_status()
    crypto_table = Table(show_header=False, box=box.SIMPLE)
    crypto_table.add_column("Property", style="cyan")
    crypto_table.add_column("Value")

    if crypto['cryptography_available']:
        crypto_table.add_row("AES Encryption", "[green]✓ Available[/green]")
    else:
        crypto_table.add_row("AES Encryption", "[yellow]✗ Not installed[/yellow]")

    crypto_table.add_row("Available Methods", ", ".join(crypto['available_methods']))
    crypto_table.add_row("Recommended", crypto['recommended'])

    console.print(Panel(crypto_table, title="[green]Cryptography[/green]", border_style="green"))

    # Channels
    channel_list = " • ".join(CHANNEL_PRESETS.keys())
    console.print(Panel(
        f"[cyan]{channel_list}[/cyan]",
        title="[cyan]Channel Presets[/cyan]",
        border_style="cyan",
    ))

    # Version info
    console.print(Panel(
        "[green]STEGOSAURUS WRECKS[/green] v2.0\n"
        "[dim]Ultimate Steganography Suite[/dim]\n\n"
        f"{TAGLINES[0]}",
        title="[magenta]About[/magenta]",
        border_style="magenta",
    ))

    console.print(f"\n{FOOTER}")


# Entry point
def main_cli():
    """Main entry point"""
    app()


if __name__ == "__main__":
    main_cli()
