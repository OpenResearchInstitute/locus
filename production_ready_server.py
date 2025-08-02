#!/usr/bin/env python3
"""
Production Conference Server (Separate Machine Only)
Designed to run on a dedicated machine, separate from stations
"""

import socket
import time
import struct
import argparse
import signal
import sys

# Import proper station ID decoder
try:
    from radio_protocol import StationIdentifier
    PROPER_DECODER_AVAILABLE = True
    print("✅ Using proper base-40 station ID decoder")
except ImportError:
    PROPER_DECODER_AVAILABLE = False
    print("⚠️  Using hex fallback for station IDs")

class ProductionConferenceServer:
    """Production conference server for separate machine deployment"""
    
    def __init__(self, listen_port=57372):
        self.listen_port = listen_port
        self.socket = None
        self.running = False
        
        # Track stations by callsign
        self.stations = {}  # callsign -> {'ip': ip, 'last_seen': time, 'frame_count': count}
        
        # Statistics
        self.stats = {
            'frames_received': 0,
            'frames_forwarded': 0,
            'unique_stations': 0,
            'decode_errors': 0,
            'start_time': time.time()
        }
        
        # Setup signal handlers for clean shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\n🛑 Received signal {signum}, shutting down...")
        self.running = False
        
    def start(self):
        """Start the production conference server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.listen_port))
            self.socket.settimeout(1.0)  # Allow periodic checking
            self.running = True
            
            print("=" * 80)
            print("📡 OPULENT VOICE CONFERENCE SERVER")
            print("=" * 80)
            print(f"📡 Listening on: 0.0.0.0:{self.listen_port}")
            print(f"🏷️  Station decoding: {'✅ Base-40 callsigns' if PROPER_DECODER_AVAILABLE else '⚠️  Hex IDs'}")
            print(f"🌍 Mode: Production (separate machine)")
            print(f"🎯 Forward strategy: IP-based routing to port {self.listen_port}")
            print("=" * 80)
            print("🚀 Server ready for connections")
            print("📊 Statistics will be shown every 60 seconds")
            print("🛑 Press Ctrl+C for graceful shutdown")
            print()
            
            frame_count = 0
            last_stats_time = time.time()
            
            while self.running:
                try:
                    frame_data, sender_addr = self.socket.recvfrom(4096)
                    frame_count += 1
                    self.stats['frames_received'] += 1
                    
                    # Process frame
                    self._process_frame(frame_data, sender_addr)
                    
                    # Periodic statistics (every 60 seconds)
                    current_time = time.time()
                    if current_time - last_stats_time >= 60.0:
                        self._print_periodic_stats()
                        last_stats_time = current_time
                    
                except socket.timeout:
                    continue  # Normal timeout for checking running flag
                except Exception as e:
                    print(f"❌ Error processing frame: {e}")
                    
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            return 1
        finally:
            self._shutdown()
            return 0
            
    def _process_frame(self, frame_data, sender_addr):
        """Process incoming frame and forward to other stations"""
        sender_ip, sender_port = sender_addr
        
        # Extract and validate callsign
        callsign = self._extract_callsign(frame_data)
        if not callsign:
            self.stats['decode_errors'] += 1
            return
        
        # Update station registry
        self._update_station(callsign, sender_ip)
        
        # Forward to all other stations
        forwarded = self._forward_frame(frame_data, callsign, sender_ip)
        self.stats['frames_forwarded'] += forwarded
        
    def _extract_callsign(self, frame_data):
        """Extract callsign using proper base-40 decoding"""
        if len(frame_data) < 12:
            return None
            
        try:
            station_bytes = frame_data[:6]
            token = frame_data[6:9]
            
            # Validate Opulent Voice token
            if token != b'\xBB\xAA\xDD':
                return None
            
            # Decode station ID
            if PROPER_DECODER_AVAILABLE:
                try:
                    station_id = StationIdentifier.from_bytes(station_bytes)
                    return str(station_id)
                except Exception:
                    # Fallback to hex if decode fails
                    return f"HEX_{station_bytes.hex().upper()[:8]}"
            else:
                return f"HEX_{station_bytes.hex().upper()[:8]}"
                
        except Exception:
            return None
    
    def _update_station(self, callsign, sender_ip):
        """Update station registry"""
        current_time = time.time()
        
        if callsign in self.stations:
            # Update existing station
            station_info = self.stations[callsign]
            station_info['last_seen'] = current_time
            station_info['frame_count'] += 1
            
            # Check for IP changes
            if station_info['ip'] != sender_ip:
                print(f"📍 {callsign}: IP changed {station_info['ip']} → {sender_ip}")
                station_info['ip'] = sender_ip
        else:
            # New station
            print(f"🆕 NEW STATION: {callsign} at {sender_ip}")
            self.stations[callsign] = {
                'ip': sender_ip,
                'last_seen': current_time,
                'frame_count': 1
            }
            self.stats['unique_stations'] += 1
    
    def _forward_frame(self, frame_data, sender_callsign, sender_ip):
        """Forward frame to all other stations"""
        forwarded_count = 0
        failed_stations = []
        
        for callsign, info in self.stations.items():
#-=-=-=-=-=-=This test determines what is being forwarded=-=-=-=-=-=-
#            NEW: Accept same IP address if different callsign             
#            if callsign != sender_callsign and info['ip'] != sender_ip:
            if callsign != sender_callsign:
                target_addr = (info['ip'], self.listen_port)
                
                try:
                    self.socket.sendto(frame_data, target_addr)
                    forwarded_count += 1
                    
                except Exception as e:
                    print(f"❌ Forward failed to {callsign} at {info['ip']}: {e}")
                    failed_stations.append(callsign)
        
        # Remove failed stations
        for callsign in failed_stations:
            print(f"🗑️  Removing unreachable station: {callsign}")
            del self.stations[callsign]
        
        return forwarded_count
    
    def _print_periodic_stats(self):
        """Print periodic statistics"""
        uptime = time.time() - self.stats['start_time']
        
        print("\n" + "=" * 60)
        print("📊 PERIODIC STATISTICS")
        print("=" * 60)
        print(f"⏰ Uptime: {uptime/3600:.1f} hours")
        print(f"📥 Frames received: {self.stats['frames_received']}")
        print(f"📤 Frames forwarded: {self.stats['frames_forwarded']}")
        print(f"👥 Active stations: {len(self.stations)}")
        print(f"❌ Decode errors: {self.stats['decode_errors']}")
        
        if self.stats['frames_received'] > 0:
            efficiency = (self.stats['frames_forwarded'] / self.stats['frames_received']) * 100
            print(f"📊 Forward efficiency: {efficiency:.1f}%")
        
        if len(self.stations) > 0:
            print(f"\n📋 Active Stations:")
            for callsign, info in self.stations.items():
                age = time.time() - info['last_seen']
                print(f"   📡 {callsign} at {info['ip']} ({info['frame_count']} frames, {age:.0f}s ago)")
        
        print("=" * 60)
        
        # Health warnings
        if len(self.stations) == 0:
            print("⚠️  No active stations - waiting for connections...")
        elif self.stats['decode_errors'] > self.stats['frames_received'] * 0.1:
            print("⚠️  High decode error rate - check frame format compatibility")
    
    def _shutdown(self):
        """Clean shutdown with final statistics"""
        if self.socket:
            self.socket.close()
            
        uptime = time.time() - self.stats['start_time']
        
        print("\n" + "=" * 80)
        print("📊 FINAL STATISTICS")
        print("=" * 80)
        print(f"⏰ Total uptime: {uptime/3600:.2f} hours")
        print(f"📥 Total frames: {self.stats['frames_received']}")
        print(f"📤 Total forwarded: {self.stats['frames_forwarded']}")
        print(f"👥 Peak stations: {self.stats['unique_stations']}")
        
        if self.stats['frames_received'] > 0:
            avg_rate = self.stats['frames_received'] / uptime
            print(f"📊 Average rate: {avg_rate:.1f} frames/second")
        
        print(f"\n🏁 Production conference server stopped")

def create_argument_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description='Production Opulent Voice Conference Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DEPLOYMENT REQUIREMENTS:
  • Must run on a separate machine from interlocutor.py stations
  • Stations connect using: python3 interlocutor.py CALL -i <SERVER_IP>
  • All stations use default port 57372 for clean routing
  
EXAMPLES:
  %(prog)s                    # Listen on default port 57372
  %(prog)s -p 8000           # Listen on custom port 8000
  %(prog)s -v                # Enable verbose logging
  
NETWORK SETUP:
  • Ensure port 57372 (or custom port) is open in firewall
  • Server listens on all interfaces (0.0.0.0)
  • Stations automatically discovered by first transmission
        """
    )
    
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=57372,
        help='Port to listen on (default: 57372)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose frame logging'
    )
    
    parser.add_argument(
        '--no-decoder-check',
        action='store_true',
        help='Skip radio_protocol.py import check'
    )
    
    return parser

def main():
    """Main entry point"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    print("📡 Production Opulent Voice Conference Server")
    print(f"📡 Version: Separate Machine Deployment")
    print(f"📡 Listen port: {args.port}")
    
    # Validate configuration
    if not (1024 <= args.port <= 65535):
        print(f"❌ Invalid port: {args.port} (must be 1024-65535)")
        return 1
    
    # Check decoder availability
    if not PROPER_DECODER_AVAILABLE and not args.no_decoder_check:
        print("\n⚠️  WARNING: radio_protocol.py not found")
        print("   Station IDs will be shown as hex codes instead of callsigns")
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            return 1
    
    print(f"\n🚀 Starting server...")
    print(f"🌍 Stations should connect with: python3 interlocutor.py CALL -i <THIS_IP>")
    
    # Create and start server
    server = ProductionConferenceServer(args.port)
    return server.start()

if __name__ == "__main__":
    exit(main())
