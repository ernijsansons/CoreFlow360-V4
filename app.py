from flask import Flask, request, jsonify
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route('/', methods=['GET'])
def welcome():
    """Welcome endpoint with current timestamp"""
    try:
        response = {
            'message': 'Welcome to CoreFlow360 V4 Flask Server',
            'timestamp': datetime.utcnow().isoformat()
        }
        logger.info('Welcome endpoint accessed')
        return jsonify(response), 200
    except Exception as e:
        logger.error(f'Error in welcome endpoint: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        response = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat()
        }
        logger.info('Health check endpoint accessed')
        return jsonify(response), 200
    except Exception as e:
        logger.error(f'Error in health check endpoint: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/echo', methods=['POST'])
def echo():
    """Echo endpoint that returns posted JSON data with timestamp"""
    try:
        if not request.is_json:
            logger.warning('Echo endpoint received non-JSON request')
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()

        if data is None:
            logger.warning('Echo endpoint received invalid JSON')
            return jsonify({'error': 'Invalid JSON data'}), 400

        response = {
            **data,
            'timestamp': datetime.utcnow().isoformat()
        }

        logger.info(f'Echo endpoint accessed with data: {data}')
        return jsonify(response), 200

    except Exception as e:
        logger.error(f'Error in echo endpoint: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    logger.warning(f'404 error: {request.url}')
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f'500 error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info('Starting Flask server on port 5000')
    app.run(host='0.0.0.0', port=5000, debug=True)
