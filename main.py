#!/usr/bin/env python3
"""
FlowTrack - Advanced Network Security Monitor
Main Application Entry Point

Usage:
    sudo python3 main.py  (Linux - requires sudo for packet sniffing)
    python main.py        (Windows - run as Administrator)
"""
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from gui.main_window import FlowTrackApp


def main():
    """Main application entry point"""
    print("=" * 60)
    print("FlowTrack - Advanced Network Security Monitor v3.0")
    print("=" * 60)
    print("Starting application...")
    print("Note: Some features require administrator/root privileges")
    print()
    
    try:
        app = FlowTrackApp()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication terminated by user")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
