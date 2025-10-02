from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json

# Try importing cvss library with correct syntax
try:
    from cvss import CVSS3
    CVSS_AVAILABLE = True
except ImportError:
    CVSS_AVAILABLE = False
    print("Warning: CVSS library not properly installed")

app = Flask(__name__)
CORS(app)

# Custom CVSS calculator implementation as fallback
class CVSSCalculator:
    """Fallback CVSS calculator if library is not available"""
    
    @staticmethod
    def calculate_cvss3(vector_string):
        """Calculate CVSS3 score from vector string"""
        metrics = {}
        
        # Parse vector string
        parts = vector_string.replace('CVSS:3.1/', '').replace('CVSS:3.0/', '').split('/')
        for part in parts:
            if ':' in part:
                key, value = part.split(':')
                metrics[key] = value
        
        # CVSS3 Base Score Calculation
        # Attack Vector (AV)
        av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        # Attack Complexity (AC)
        ac_scores = {'L': 0.77, 'H': 0.44}
        # Privileges Required (PR)
        pr_scores = {
            'N': {'U': 0.85, 'C': 0.85},
            'L': {'U': 0.62, 'C': 0.68},
            'H': {'U': 0.27, 'C': 0.5}
        }
        # User Interaction (UI)
        ui_scores = {'N': 0.85, 'R': 0.62}
        # Scope (S)
        scope = metrics.get('S', 'U')
        # CIA Impact
        cia_scores = {'N': 0, 'L': 0.22, 'H': 0.56}
        
        # Get metric values
        av = av_scores.get(metrics.get('AV', 'N'), 0.85)
        ac = ac_scores.get(metrics.get('AC', 'L'), 0.77)
        pr = pr_scores.get(metrics.get('PR', 'N'), {}).get(scope, 0.85)
        ui = ui_scores.get(metrics.get('UI', 'N'), 0.85)
        c = cia_scores.get(metrics.get('C', 'N'), 0)
        i = cia_scores.get(metrics.get('I', 'N'), 0)
        a = cia_scores.get(metrics.get('A', 'N'), 0)
        
        # Calculate Impact Score
        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if scope == 'U':
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        
        # Calculate Exploitability Score
        exploitability = 8.22 * av * ac * pr * ui
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0
        elif scope == 'U':
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)
        
        # Round to one decimal place
        base_score = round(base_score, 1)
        impact = round(impact, 1)
        exploitability = round(exploitability, 1)
        
        return {
            'base_score': base_score,
            'impact_score': impact,
            'exploitability_score': exploitability,
            'temporal_score': base_score,  # Same as base for now
            'environmental_score': base_score  # Same as base for now
        }
    
    @staticmethod
    def calculate_cvss2(vector_string):
        """Calculate CVSS2 score from vector string"""
        metrics = {}
        
        # Parse vector string
        parts = vector_string.split('/')
        for part in parts:
            if ':' in part:
                key, value = part.split(':')
                metrics[key] = value
        
        # CVSS2 Base Score Calculation
        # Access Vector (AV)
        av_scores = {'L': 0.395, 'A': 0.646, 'N': 1.0}
        # Access Complexity (AC)
        ac_scores = {'H': 0.35, 'M': 0.61, 'L': 0.71}
        # Authentication (Au)
        au_scores = {'M': 0.45, 'S': 0.56, 'N': 0.704}
        # CIA Impact
        cia_scores = {'N': 0.0, 'P': 0.275, 'C': 0.660}
        
        # Get metric values
        av = av_scores.get(metrics.get('AV', 'N'), 1.0)
        ac = ac_scores.get(metrics.get('AC', 'L'), 0.71)
        au = au_scores.get(metrics.get('Au', 'N'), 0.704)
        c = cia_scores.get(metrics.get('C', 'N'), 0.0)
        i = cia_scores.get(metrics.get('I', 'N'), 0.0)
        a = cia_scores.get(metrics.get('A', 'N'), 0.0)
        
        # Calculate Impact Score
        impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
        
        # Calculate Exploitability Score
        exploitability = 20 * av * ac * au
        
        # Calculate Base Score
        f_impact = 0 if impact == 0 else 1.176
        base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
        
        # Round to one decimal place
        base_score = round(min(10, max(0, base_score)), 1)
        impact = round(impact, 1)
        exploitability = round(exploitability, 1)
        
        return {
            'base_score': base_score,
            'impact_score': impact,
            'exploitability_score': exploitability,
            'temporal_score': base_score,  # Same as base for now
            'environmental_score': base_score  # Same as base for now
        }

# CVSS3.1 Metrics definitions
CVSS3_METRICS = {
    'AV': {
        'name': 'Attack Vector',
        'options': {
            'N': 'Network',
            'A': 'Adjacent',
            'L': 'Local',
            'P': 'Physical'
        }
    },
    'AC': {
        'name': 'Attack Complexity',
        'options': {
            'L': 'Low',
            'H': 'High'
        }
    },
    'PR': {
        'name': 'Privileges Required',
        'options': {
            'N': 'None',
            'L': 'Low',
            'H': 'High'
        }
    },
    'UI': {
        'name': 'User Interaction',
        'options': {
            'N': 'None',
            'R': 'Required'
        }
    },
    'S': {
        'name': 'Scope',
        'options': {
            'U': 'Unchanged',
            'C': 'Changed'
        }
    },
    'C': {
        'name': 'Confidentiality Impact',
        'options': {
            'N': 'None',
            'L': 'Low',
            'H': 'High'
        }
    },
    'I': {
        'name': 'Integrity Impact',
        'options': {
            'N': 'None',
            'L': 'Low',
            'H': 'High'
        }
    },
    'A': {
        'name': 'Availability Impact',
        'options': {
            'N': 'None',
            'L': 'Low',
            'H': 'High'
        }
    }
}

# CVSS2 Metrics definitions
CVSS2_METRICS = {
    'AV': {
        'name': 'Access Vector',
        'options': {
            'L': 'Local',
            'A': 'Adjacent Network',
            'N': 'Network'
        }
    },
    'AC': {
        'name': 'Access Complexity',
        'options': {
            'H': 'High',
            'M': 'Medium',
            'L': 'Low'
        }
    },
    'Au': {
        'name': 'Authentication',
        'options': {
            'M': 'Multiple',
            'S': 'Single',
            'N': 'None'
        }
    },
    'C': {
        'name': 'Confidentiality Impact',
        'options': {
            'N': 'None',
            'P': 'Partial',
            'C': 'Complete'
        }
    },
    'I': {
        'name': 'Integrity Impact',
        'options': {
            'N': 'None',
            'P': 'Partial',
            'C': 'Complete'
        }
    },
    'A': {
        'name': 'Availability Impact',
        'options': {
            'N': 'None',
            'P': 'Partial',
            'C': 'Complete'
        }
    }
}

def get_severity_rating(score, version='3'):
    """Get severity rating based on CVSS score"""
    if version == '3':
        if score == 0.0:
            return 'None', 'info'
        elif 0.1 <= score <= 3.9:
            return 'Low', 'success'
        elif 4.0 <= score <= 6.9:
            return 'Medium', 'warning'
        elif 7.0 <= score <= 8.9:
            return 'High', 'danger'
        elif 9.0 <= score <= 10.0:
            return 'Critical', 'critical'
    else:  # CVSS2
        if 0.0 <= score <= 3.9:
            return 'Low', 'success'
        elif 4.0 <= score <= 6.9:
            return 'Medium', 'warning'
        elif 7.0 <= score <= 10.0:
            return 'High', 'danger'
    return 'Unknown', 'secondary'

@app.route('/')
def index():
    return render_template('index.html', 
                         cvss3_metrics=CVSS3_METRICS,
                         cvss2_metrics=CVSS2_METRICS)

@app.route('/calculate', methods=['POST'])
def calculate_cvss():
    try:
        data = request.json
        version = data.get('version', '3.1')
        vector_string = data.get('vector_string', '')
        
        if not vector_string:
            return jsonify({'error': 'Vector string is required'}), 400
        
        calculator = CVSSCalculator()
        
        # Calculate based on version
        if version in ['3.0', '3.1']:
            # Try using the library first if available
            if CVSS_AVAILABLE:
                try:
                    cvss_vector = CVSS3(vector_string)
                    base_score = cvss_vector.base_score
                    scores = {
                        'base': base_score,
                        'impact': cvss_vector.impact_score,
                        'exploitability': cvss_vector.exploitability_score
                    }
                    environmental_score = cvss_vector.environmental_score
                    temporal_score = cvss_vector.temporal_score
                except:
                    # Fallback to custom calculator
                    result = calculator.calculate_cvss3(vector_string)
                    base_score = result['base_score']
                    scores = {
                        'base': base_score,
                        'impact': result['impact_score'],
                        'exploitability': result['exploitability_score']
                    }
                    environmental_score = result['environmental_score']
                    temporal_score = result['temporal_score']
            else:
                # Use custom calculator
                result = calculator.calculate_cvss3(vector_string)
                base_score = result['base_score']
                scores = {
                    'base': base_score,
                    'impact': result['impact_score'],
                    'exploitability': result['exploitability_score']
                }
                environmental_score = result['environmental_score']
                temporal_score = result['temporal_score']
            
            severity, severity_class = get_severity_rating(base_score, '3')
            
        else:  # CVSS2
            result = calculator.calculate_cvss2(vector_string)
            base_score = result['base_score']
            scores = {
                'base': base_score,
                'impact': result['impact_score'],
                'exploitability': result['exploitability_score']
            }
            environmental_score = result['environmental_score']
            temporal_score = result['temporal_score']
            severity, severity_class = get_severity_rating(base_score, '2')
        
        return jsonify({
            'success': True,
            'version': version,
            'vector_string': vector_string,
            'base_score': base_score,
            'severity': severity,
            'severity_class': severity_class,
            'environmental_score': environmental_score,
            'temporal_score': temporal_score,
            'scores': scores
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/parse_vector', methods=['POST'])
def parse_vector():
    """Parse a CVSS vector string and return its components"""
    try:
        data = request.json
        vector_string = data.get('vector_string', '')
        version = data.get('version', '3.1')
        
        if not vector_string:
            return jsonify({'error': 'Vector string is required'}), 400
        
        # Parse the vector string
        components = {}
        if version in ['3.0', '3.1']:
            if vector_string.startswith('CVSS:3'):
                parts = vector_string.split('/')
                for part in parts[1:]:  # Skip the CVSS:3.x part
                    if ':' in part:
                        key, value = part.split(':')
                        components[key] = value
        else:  # CVSS2
            parts = vector_string.split('/')
            for part in parts:
                if ':' in part:
                    key, value = part.split(':')
                    components[key] = value
        
        return jsonify({
            'success': True,
            'components': components
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)