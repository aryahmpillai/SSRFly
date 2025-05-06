#!/usr/bin/env python3
"""
SSRFly Web UI - A web interface for the SSRFly SSRF testing tool
"""

import os
import sys
import time
import logging
import threading
import json
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for

from ssrfly import scan_url
from utils import validate_url

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "ssrfly-development-key")

# Store scan results in memory
scan_results = {}
active_scans = {}

@app.route('/')
def index():
    """Render the home page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a scan based on the provided URL or file."""
    target_url = request.form.get('url')
    urls_file = request.files.get('file')
    
    if not target_url and not urls_file:
        flash('Please provide a URL or a file containing URLs', 'error')
        return redirect(url_for('index'))
    
    urls_to_scan = []
    
    # Process single URL
    if target_url:
        if validate_url(target_url):
            urls_to_scan.append(target_url)
        else:
            flash('Invalid URL format', 'error')
            return redirect(url_for('index'))
    
    # Process file
    if urls_file:
        try:
            file_content = urls_file.read().decode('utf-8')
            for line in file_content.splitlines():
                url = line.strip()
                if validate_url(url):
                    urls_to_scan.append(url)
        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'error')
            return redirect(url_for('index'))
    
    if not urls_to_scan:
        flash('No valid URLs found', 'error')
        return redirect(url_for('index'))
    
    # Generate a unique scan ID
    scan_id = f"scan_{int(time.time())}"
    
    # Initialize scan data
    scan_results[scan_id] = {
        'status': 'in_progress',
        'start_time': time.time(),
        'total_urls': len(urls_to_scan),
        'scanned_urls': 0,
        'urls': urls_to_scan,
        'results': {}
    }
    
    # Start scan in background
    threading.Thread(target=_run_scan, args=(scan_id, urls_to_scan)).start()
    
    # Redirect to results page
    return redirect(url_for('scan_results_page', scan_id=scan_id))

def _run_scan(scan_id, urls):
    """Run scan in background thread."""
    active_scans[scan_id] = True
    try:
        for url in urls:
            if not active_scans.get(scan_id, False):
                break  # Stop if scan was cancelled
                
            result = scan_url(url, timeout=10)
            scan_results[scan_id]['results'][url] = result
            scan_results[scan_id]['scanned_urls'] += 1
            
        scan_results[scan_id]['status'] = 'completed'
    except Exception as e:
        scan_results[scan_id]['status'] = 'error'
        scan_results[scan_id]['error'] = str(e)
    finally:
        scan_results[scan_id]['end_time'] = time.time()
        if scan_id in active_scans:
            del active_scans[scan_id]

@app.route('/results/<scan_id>')
def scan_results_page(scan_id):
    """Display results for a specific scan."""
    if scan_id not in scan_results:
        flash('Scan not found', 'error')
        return redirect(url_for('index'))
    
    return render_template('results.html', scan_id=scan_id)

@app.route('/api/results/<scan_id>')
def api_scan_results(scan_id):
    """API endpoint to get scan results."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/cancel/<scan_id>')
def cancel_scan(scan_id):
    """Cancel an in-progress scan."""
    if scan_id in active_scans:
        active_scans[scan_id] = False
        scan_results[scan_id]['status'] = 'cancelled'
        flash('Scan cancelled', 'info')
    
    return redirect(url_for('scan_results_page', scan_id=scan_id))

@app.route('/api/validate-url', methods=['POST'])
def api_validate_url():
    """API endpoint to validate a URL."""
    url = request.json.get('url', '')
    is_valid = validate_url(url)
    return jsonify({'valid': is_valid})

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)