from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required

from crypto_hunter_web.models import AnalysisFile, Finding
from crypto_hunter_web.services.search_service import SearchService
from crypto_hunter_web.utils.decorators import api_endpoint

# Create the search blueprint
search_bp = Blueprint('search', __name__, url_prefix='/search')

@search_bp.route('/')
@login_required
def search_page():
    """Render the search page"""
    return render_template('search/search.html', title='Search')

@search_bp.route('/results')
@login_required
def search_results():
    """Render search results page"""
    query = request.args.get('q', '')
    return render_template('search/results.html', title='Search Results', query=query)

# Import the API routes from search_api.py to maintain functionality
from crypto_hunter_web.routes.search_api import search_api_bp