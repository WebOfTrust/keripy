# -*- encoding: utf-8 -*-
"""
Windows-specific utilities for testing
"""
import socket
import sys


def find_available_port(start_port=8000, max_attempts=100):
    """
    Find an available port for Windows testing
    
    Windows blocks access to ports in the 5000-5999 range with WinError 10013.
    This function finds an available port starting from 8000.
    
    Args:
        start_port (int): Port to start searching from (default: 8000)
        max_attempts (int): Maximum number of ports to try
        
    Returns:
        int: Available port number
        
    Raises:
        RuntimeError: If no available port is found
    """
    for port in range(start_port, start_port + max_attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('127.0.0.1', port))
            sock.close()
            return port
        except socket.error:
            sock.close()
            continue
    
    raise RuntimeError(f"No available ports found in range {start_port}-{start_port + max_attempts}")


def get_test_ports(count=5):
    """
    Get a list of available ports for testing
    
    Args:
        count (int): Number of ports to find
        
    Returns:
        list[int]: List of available port numbers
    """
    ports = []
    start_port = 8000
    
    for i in range(count):
        port = find_available_port(start_port + len(ports))
        ports.append(port)
    
    return ports


# Windows-specific port mappings for tests
if sys.platform == 'win32':
    WINDOWS_TEST_PORTS = get_test_ports(10)
    
    # Map commonly used test ports to available Windows ports
    PORT_MAPPING = {
        5555: WINDOWS_TEST_PORTS[0],  # test_essr_stream uses this
        5634: WINDOWS_TEST_PORTS[1],  # test_essr_mbx tcpPort 
        5644: WINDOWS_TEST_PORTS[2],  # test_essr_mbx httpPort
        5642: WINDOWS_TEST_PORTS[3],  # other witness ports
        5643: WINDOWS_TEST_PORTS[4],  # other witness ports
        5632: WINDOWS_TEST_PORTS[5],  # other witness ports
        5633: WINDOWS_TEST_PORTS[6],  # other witness ports
        5631: WINDOWS_TEST_PORTS[7],  # default witness ports
        5635: WINDOWS_TEST_PORTS[8],  # other witness ports
        5645: WINDOWS_TEST_PORTS[9],  # other witness ports
    }
else:
    PORT_MAPPING = {}


def get_available_port(requested_port):
    """
    Get an available port, using Windows mapping if needed
    
    Args:
        requested_port (int): The port originally requested
        
    Returns:
        int: Available port (mapped on Windows, original on other platforms)
    """
    if sys.platform == 'win32' and requested_port in PORT_MAPPING:
        return PORT_MAPPING[requested_port]
    return requested_port