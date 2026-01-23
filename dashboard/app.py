#!/usr/bin/env python3
"""
Professional Flask Dashboard for Advanced LLMs Cybersecurity Platform
Designed for PhD ML students with comprehensive analytics and model management.
"""

from flask import Flask, render_template, jsonify, request, send_file
import json
import pandas as pd
import numpy as np
from pathlib import Path
import logging
import sys
from datetime import datetime, timedelta
import plotly.graph_objs as go
import plotly.utils
from plotly.subplots import make_subplots

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersec-llm-dashboard-2024'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DashboardDataManager:
    """Manages data for the dashboard."""
    
    def __init__(self):
        self.output_dir = Path("output")  # Fixed path - remove ../
        self.models_dir = Path("models")   # Fixed path - remove ../
        self.data_dir = Path("data")       # Fixed path - remove ../
        
    def get_system_status(self):
        """Get overall system status."""
        status = {
            "timestamp": datetime.now().isoformat(),
            "modules": {
                "threat_detection": self._check_module_status("threat_detection"),
                "digital_forensics": self._check_module_status("digital_forensics"),
                "soc_automation": self._check_module_status("soc_automation"),
                "security_challenges": self._check_module_status("security_challenges")
            },
            "datasets": self._get_dataset_status(),
            "models": self._get_model_status()
        }
        return status
    
    def _check_module_status(self, module_name):
        """Check if module report exists and is recent."""
        report_file = self.output_dir / f"{module_name}_report.json"
        if report_file.exists():
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                return {
                    "status": "active",
                    "last_run": report_file.stat().st_mtime,
                    "data_available": True
                }
            except:
                return {"status": "error", "data_available": False}
        return {"status": "inactive", "data_available": False}
    
    def _get_dataset_status(self):
        """Get dataset availability status."""
        manifest_file = self.data_dir / "manifest.json"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                return manifest.get("datasets", {})
            except:
                return {}
        return {}
    
    def _get_model_status(self):
        """Get trained model status."""
        models = {}
        if self.models_dir.exists():
            for model_dir in self.models_dir.iterdir():
                if model_dir.is_dir():
                    config_file = model_dir / "config.json"
                    if config_file.exists():
                        models[model_dir.name] = {
                            "status": "trained",
                            "path": str(model_dir),
                            "size": sum(f.stat().st_size for f in model_dir.rglob('*') if f.is_file())
                        }
        return models
    
    def get_threat_analytics(self):
        """Get threat detection analytics."""
        report_file = self.output_dir / "threat_detection_report.json"
        if report_file.exists():
            try:
                with open(report_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def get_forensics_analytics(self):
        """Get digital forensics analytics."""
        report_file = self.output_dir / "forensic_report.json"
        if report_file.exists():
            try:
                with open(report_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def get_soc_analytics(self):
        """Get SOC automation analytics."""
        report_file = self.output_dir / "soc_automation_report.json"
        if report_file.exists():
            try:
                with open(report_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def get_security_analytics(self):
        """Get security challenges analytics."""
        report_file = self.output_dir / "security_analysis_report.json"
        if report_file.exists():
            try:
                with open(report_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def get_training_metrics(self):
        """Get model training metrics."""
        # Try output directory first, then models directory
        training_file = self.output_dir / "training_summary.json"
        if not training_file.exists():
            training_file = self.models_dir / "training_summary.json"
            
        if training_file.exists():
            try:
                with open(training_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

# Initialize data manager
data_manager = DashboardDataManager()

@app.route('/')
def dashboard():
    """Main dashboard page."""
    return render_template('dashboard.html')

@app.route('/api/system-status')
def system_status():
    """API endpoint for system status."""
    try:
        return jsonify(data_manager.get_system_status())
    except Exception as e:
        logger.error(f"Error in system-status endpoint: {e}")
        return jsonify({"error": "Failed to load system status", "modules": {}})

@app.route('/api/threat-analytics')
def threat_analytics():
    """API endpoint for threat detection analytics."""
    try:
        return jsonify(data_manager.get_threat_analytics())
    except Exception as e:
        logger.error(f"Error in threat-analytics endpoint: {e}")
        return jsonify({"error": "Failed to load threat analytics", "summary": {}})

@app.route('/api/forensics-analytics')
def forensics_analytics():
    """API endpoint for forensics analytics."""
    try:
        return jsonify(data_manager.get_forensics_analytics())
    except Exception as e:
        logger.error(f"Error in forensics-analytics endpoint: {e}")
        return jsonify({"error": "Failed to load forensics analytics"})

@app.route('/api/soc-analytics')
def soc_analytics():
    """API endpoint for SOC analytics."""
    try:
        return jsonify(data_manager.get_soc_analytics())
    except Exception as e:
        logger.error(f"Error in soc-analytics endpoint: {e}")
        return jsonify({"error": "Failed to load SOC analytics", "summary": {}, "automation_metrics": {}})

@app.route('/api/security-analytics')
def security_analytics():
    """API endpoint for security analytics."""
    try:
        return jsonify(data_manager.get_security_analytics())
    except Exception as e:
        logger.error(f"Error in security-analytics endpoint: {e}")
        return jsonify({"error": "Failed to load security analytics"})

@app.route('/api/training-metrics')
def training_metrics():
    """API endpoint for training metrics."""
    try:
        return jsonify(data_manager.get_training_metrics())
    except Exception as e:
        logger.error(f"Error in training-metrics endpoint: {e}")
        return jsonify({"error": "Failed to load training metrics", "results": {}})

@app.route('/api/threat-distribution-chart')
def threat_distribution_chart():
    """Generate threat distribution chart."""
    try:
        threat_data = data_manager.get_threat_analytics()
        
        if not threat_data or 'threat_distribution' not in threat_data:
            return jsonify({"error": "No threat data available"})
        
        distribution = threat_data['threat_distribution']
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(distribution.keys()),
                y=list(distribution.values()),
                marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7']
            )
        ])
        
        fig.update_layout(
            title="Threat Type Distribution",
            xaxis_title="Threat Type",
            yaxis_title="Count",
            template="plotly_white",
            height=400
        )
        
        return jsonify(json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig)))
    except Exception as e:
        logger.error(f"Error in threat-distribution-chart endpoint: {e}")
        return jsonify({"error": "Failed to generate threat distribution chart"})

@app.route('/api/soc-metrics-chart')
def soc_metrics_chart():
    """Generate SOC automation metrics chart."""
    try:
        soc_data = data_manager.get_soc_analytics()
        
        if not soc_data or 'automation_metrics' not in soc_data:
            return jsonify({"error": "No SOC data available"})
        
        metrics = soc_data['automation_metrics']
        
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=('Automation vs Manual Actions', 'Workload Reduction'),
            specs=[[{"type": "pie"}, {"type": "indicator"}]],
            column_widths=[0.5, 0.5]  # Equal width for both subplots
        )
        
        # Pie chart for automation vs manual
        fig.add_trace(
            go.Pie(
                labels=['Automated', 'Manual'],
                values=[metrics.get('automated_actions', 0), metrics.get('manual_actions', 0)],
                hole=0.3,
                domain={'x': [0, 0.45], 'y': [0, 1]}  # Constrain pie chart to left side
            ),
            row=1, col=1
        )
        
        # Gauge for workload reduction
        workload_reduction = float(metrics.get('workload_reduction', '0%').replace('%', ''))
        fig.add_trace(
            go.Indicator(
                mode="gauge+number",
                value=workload_reduction,
                domain={'x': [0.55, 1], 'y': [0.2, 0.8]},  # Constrain gauge to right side
                title={'text': "Workload Reduction %", 'font': {'size': 14}},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 50], 'color': "lightgray"},
                        {'range': [50, 80], 'color': "gray"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ),
            row=1, col=2
        )
        
        fig.update_layout(
            height=400, 
            template="plotly_white",
            showlegend=True,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        return jsonify(json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig)))
    except Exception as e:
        logger.error(f"Error in soc-metrics-chart endpoint: {e}")
        return jsonify({"error": "Failed to generate SOC metrics chart"})

@app.route('/api/training-progress-chart')
def training_progress_chart():
    """Generate training progress chart."""
    try:
        training_data = data_manager.get_training_metrics()
        
        if not training_data or 'results' not in training_data:
            return jsonify({"error": "No training data available"})
        
        results = training_data['results']
        
        tasks = []
        train_losses = []
        eval_losses = []
        accuracies = []
        
        for task, metrics in results.items():
            if 'training_loss' in metrics:
                tasks.append(task.replace('_', ' ').title())
                train_losses.append(metrics.get('training_loss', 0))
                eval_losses.append(metrics.get('eval_loss', 0))
                accuracies.append(metrics.get('eval_accuracy', 0))
        
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Training Loss', 'Validation Loss', 'Accuracy', 'Model Comparison'),
            specs=[[{"type": "bar"}, {"type": "bar"}],
                   [{"type": "bar"}, {"type": "scatter"}]]
        )
        
        # Training loss
        fig.add_trace(
            go.Bar(x=tasks, y=train_losses, name="Training Loss", marker_color='#FF6B6B'),
            row=1, col=1
        )
        
        # Validation loss
        fig.add_trace(
            go.Bar(x=tasks, y=eval_losses, name="Validation Loss", marker_color='#4ECDC4'),
            row=1, col=2
        )
        
        # Accuracy
        fig.add_trace(
            go.Bar(x=tasks, y=accuracies, name="Accuracy", marker_color='#45B7D1'),
            row=2, col=1
        )
        
        # Model comparison scatter
        fig.add_trace(
            go.Scatter(
                x=eval_losses, y=accuracies, mode='markers+text',
                text=tasks, textposition="top center",
                marker=dict(size=12, color='#96CEB4'),
                name="Loss vs Accuracy"
            ),
            row=2, col=2
        )
        
        fig.update_layout(height=600, template="plotly_white", showlegend=False)
        
        return jsonify(json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig)))
    except Exception as e:
        logger.error(f"Error in training-progress-chart endpoint: {e}")
        return jsonify({"error": "Failed to generate training progress chart"})

@app.route('/models')
def models_page():
    """Models management page."""
    return render_template('models.html')

@app.route('/analytics')
def analytics_page():
    """Analytics page."""
    return render_template('analytics.html')

@app.route('/datasets')
def datasets_page():
    """Datasets management page."""
    return render_template('datasets.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)