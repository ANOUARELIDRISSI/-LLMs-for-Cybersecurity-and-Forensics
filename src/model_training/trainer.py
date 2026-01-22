#!/usr/bin/env python3
"""
Model Training Module for Advanced LLMs Cybersecurity
Implements training pipelines for specialized cybersecurity models.
"""

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification,
    TrainingArguments, Trainer, EarlyStoppingCallback
)
import pandas as pd
import numpy as np
from pathlib import Path
import json
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TrainingConfig:
    """Training configuration parameters."""
    model_name: str = "distilbert-base-uncased"
    max_length: int = 512
    batch_size: int = 16
    learning_rate: float = 2e-5
    num_epochs: int = 3
    warmup_steps: int = 500
    weight_decay: float = 0.01
    output_dir: str = "models"
    save_steps: int = 500
    eval_steps: int = 500
    logging_steps: int = 100

class CybersecurityDataset(Dataset):
    """Custom dataset for cybersecurity text classification."""
    
    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_length: int = 512):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]
        
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

class CybersecurityModelTrainer:
    """Trainer for cybersecurity-specific models."""
    
    def __init__(self, config: TrainingConfig):
        self.config = config
        self.tokenizer = None
        self.model = None
        self.trainer = None
        
        # Create output directory
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Label mappings for different tasks
        self.label_mappings = {
            "threat_detection": {
                0: "benign",
                1: "malware", 
                2: "phishing",
                3: "network_attack",
                4: "data_breach"
            },
            "log_classification": {
                0: "normal",
                1: "suspicious",
                2: "malicious"
            },
            "vulnerability_severity": {
                0: "low",
                1: "medium", 
                2: "high",
                3: "critical"
            }
        }
    
    def load_and_prepare_data(self, data_path: str, task_type: str = "threat_detection") -> Tuple[List[str], List[int]]:
        """Load and prepare training data from various sources."""
        texts = []
        labels = []
        
        data_path = Path(data_path)
        
        if task_type == "threat_detection":
            texts, labels = self._prepare_threat_detection_data(data_path)
        elif task_type == "log_classification":
            texts, labels = self._prepare_log_classification_data(data_path)
        elif task_type == "vulnerability_severity":
            texts, labels = self._prepare_vulnerability_data(data_path)
        
        logger.info(f"Prepared {len(texts)} samples for {task_type}")
        return texts, labels
    
    def _prepare_threat_detection_data(self, data_path: Path) -> Tuple[List[str], List[int]]:
        """Prepare threat detection training data."""
        texts = []
        labels = []
        
        # Load malware URLs if available
        malware_urls_path = data_path / "malware_urls"
        if malware_urls_path.exists():
            for file_path in malware_urls_path.glob("*.csv"):
                try:
                    df = pd.read_csv(file_path)
                    if 'url' in df.columns and 'type' in df.columns:
                        for _, row in df.iterrows():
                            texts.append(str(row['url']))
                            # Map URL types to threat categories
                            if 'malware' in str(row['type']).lower():
                                labels.append(1)  # malware
                            elif 'phishing' in str(row['type']).lower():
                                labels.append(2)  # phishing
                            else:
                                labels.append(0)  # benign
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
        
        # Load phishing emails if available
        phishing_path = data_path / "phishing"
        if phishing_path.exists():
            for file_path in phishing_path.glob("*.csv"):
                try:
                    df = pd.read_csv(file_path)
                    if 'text' in df.columns and 'label' in df.columns:
                        for _, row in df.iterrows():
                            texts.append(str(row['text']))
                            labels.append(2 if row['label'] == 1 else 0)  # phishing or benign
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
        
        # Generate synthetic data if no real data available
        if len(texts) == 0:
            texts, labels = self._generate_synthetic_threat_data()
        
        return texts, labels
    
    def _prepare_log_classification_data(self, data_path: Path) -> Tuple[List[str], List[int]]:
        """Prepare log classification training data."""
        texts = []
        labels = []
        
        # Load security logs
        log_paths = [
            data_path / "security_logs",
            data_path / "network_logs"
        ]
        
        for log_path in log_paths:
            if log_path.exists():
                for file_path in log_path.glob("*.log"):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    texts.append(line)
                                    # Simple heuristic labeling
                                    if any(keyword in line.lower() for keyword in ['error', 'failed', 'denied', 'attack']):
                                        labels.append(1)  # suspicious
                                    elif any(keyword in line.lower() for keyword in ['malware', 'virus', 'trojan', 'breach']):
                                        labels.append(2)  # malicious
                                    else:
                                        labels.append(0)  # normal
                    except Exception as e:
                        logger.warning(f"Error processing {file_path}: {e}")
        
        # Generate synthetic data if needed
        if len(texts) == 0:
            texts, labels = self._generate_synthetic_log_data()
        
        return texts, labels
    
    def _prepare_vulnerability_data(self, data_path: Path) -> Tuple[List[str], List[int]]:
        """Prepare vulnerability severity classification data."""
        texts = []
        labels = []
        
        vuln_path = data_path / "vulnerabilities"
        if vuln_path.exists():
            for file_path in vuln_path.glob("*.json"):
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        
                    # Process NVD CVE data
                    if 'vulnerabilities' in data:
                        for vuln in data['vulnerabilities']:
                            cve = vuln.get('cve', {})
                            description = cve.get('descriptions', [{}])[0].get('value', '')
                            
                            if description:
                                texts.append(description)
                                
                                # Map CVSS score to severity
                                metrics = cve.get('metrics', {})
                                cvss_score = 0.0
                                
                                if 'cvssMetricV31' in metrics:
                                    cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                                elif 'cvssMetricV30' in metrics:
                                    cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                                
                                # Map score to label
                                if cvss_score >= 9.0:
                                    labels.append(3)  # critical
                                elif cvss_score >= 7.0:
                                    labels.append(2)  # high
                                elif cvss_score >= 4.0:
                                    labels.append(1)  # medium
                                else:
                                    labels.append(0)  # low
                                    
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
        
        # Generate synthetic data if needed
        if len(texts) == 0:
            texts, labels = self._generate_synthetic_vulnerability_data()
        
        return texts, labels
    
    def _generate_synthetic_threat_data(self) -> Tuple[List[str], List[int]]:
        """Generate synthetic threat detection data."""
        synthetic_data = [
            ("Normal web browsing activity", 0),
            ("User login successful", 0),
            ("File download completed", 0),
            ("Malware.exe detected in downloads folder", 1),
            ("Trojan horse activity identified", 1),
            ("Ransomware encryption detected", 1),
            ("Phishing email with suspicious link", 2),
            ("Fake banking website detected", 2),
            ("Social engineering attempt via email", 2),
            ("Port scan detected from external IP", 3),
            ("DDoS attack in progress", 3),
            ("SQL injection attempt blocked", 3),
            ("Unauthorized data access detected", 4),
            ("Sensitive file exfiltration attempt", 4),
            ("Database breach detected", 4)
        ]
        
        # Expand synthetic data
        expanded_data = []
        for text, label in synthetic_data:
            for i in range(10):  # Create 10 variations
                expanded_data.append((f"{text} - variant {i}", label))
        
        texts, labels = zip(*expanded_data)
        return list(texts), list(labels)
    
    def _generate_synthetic_log_data(self) -> Tuple[List[str], List[int]]:
        """Generate synthetic log classification data."""
        synthetic_logs = [
            ("INFO: User login successful from 192.168.1.100", 0),
            ("INFO: File access granted to user.txt", 0),
            ("INFO: System backup completed successfully", 0),
            ("WARNING: Multiple failed login attempts detected", 1),
            ("WARNING: Unusual network traffic pattern", 1),
            ("ERROR: Access denied to sensitive directory", 1),
            ("CRITICAL: Malware signature detected", 2),
            ("ALERT: Data exfiltration attempt blocked", 2),
            ("CRITICAL: System compromise detected", 2)
        ]
        
        # Expand synthetic data
        expanded_data = []
        for log, label in synthetic_logs:
            for i in range(20):  # Create 20 variations
                expanded_data.append((f"{log} [ID:{i:04d}]", label))
        
        texts, labels = zip(*expanded_data)
        return list(texts), list(labels)
    
    def _generate_synthetic_vulnerability_data(self) -> Tuple[List[str], List[int]]:
        """Generate synthetic vulnerability data."""
        synthetic_vulns = [
            ("Minor configuration issue in web server", 0),
            ("Information disclosure in application logs", 0),
            ("Cross-site scripting vulnerability in form validation", 1),
            ("SQL injection vulnerability in user input", 1),
            ("Buffer overflow in network service", 2),
            ("Remote code execution in web application", 2),
            ("Critical authentication bypass vulnerability", 3),
            ("Zero-day exploit allowing full system compromise", 3)
        ]
        
        # Expand synthetic data
        expanded_data = []
        for vuln, label in synthetic_vulns:
            for i in range(15):  # Create 15 variations
                expanded_data.append((f"{vuln} - CVE-2024-{1000+i}", label))
        
        texts, labels = zip(*expanded_data)
        return list(texts), list(labels)
    
    def initialize_model(self, num_labels: int):
        """Initialize tokenizer and model."""
        logger.info(f"Initializing model: {self.config.model_name}")
        
        self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.config.model_name,
            num_labels=num_labels
        )
        
        # Add padding token if not present
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
    
    def train_model(self, texts: List[str], labels: List[int], task_type: str = "threat_detection"):
        """Train the cybersecurity model."""
        logger.info(f"Starting training for {task_type}")
        
        # Initialize model
        num_labels = len(set(labels))
        self.initialize_model(num_labels)
        
        # Split data
        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Create datasets
        train_dataset = CybersecurityDataset(
            train_texts, train_labels, self.tokenizer, self.config.max_length
        )
        val_dataset = CybersecurityDataset(
            val_texts, val_labels, self.tokenizer, self.config.max_length
        )
        
        # Training arguments
        training_args = TrainingArguments(
            output_dir=str(self.output_dir / f"{task_type}_model"),
            num_train_epochs=self.config.num_epochs,
            per_device_train_batch_size=self.config.batch_size,
            per_device_eval_batch_size=self.config.batch_size,
            warmup_steps=self.config.warmup_steps,
            weight_decay=self.config.weight_decay,
            logging_dir=str(self.output_dir / "logs"),
            logging_steps=self.config.logging_steps,
            evaluation_strategy="steps",
            eval_steps=self.config.eval_steps,
            save_steps=self.config.save_steps,
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            save_total_limit=2,
            report_to=None  # Disable wandb/tensorboard
        )
        
        # Initialize trainer
        self.trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=self.compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
        )
        
        # Train model
        logger.info("Starting training...")
        train_result = self.trainer.train()
        
        # Save model and tokenizer
        model_path = self.output_dir / f"{task_type}_model_final"
        self.trainer.save_model(str(model_path))
        self.tokenizer.save_pretrained(str(model_path))
        
        # Evaluate model
        eval_result = self.trainer.evaluate()
        
        # Generate training report
        training_report = {
            "task_type": task_type,
            "model_name": self.config.model_name,
            "num_labels": num_labels,
            "train_samples": len(train_texts),
            "val_samples": len(val_texts),
            "training_loss": train_result.training_loss,
            "eval_loss": eval_result["eval_loss"],
            "eval_accuracy": eval_result.get("eval_accuracy", 0),
            "model_path": str(model_path),
            "label_mapping": self.label_mappings.get(task_type, {})
        }
        
        # Save training report
        with open(self.output_dir / f"{task_type}_training_report.json", 'w') as f:
            json.dump(training_report, f, indent=2)
        
        logger.info(f"Training completed. Model saved to {model_path}")
        return training_report
    
    def compute_metrics(self, eval_pred):
        """Compute evaluation metrics."""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        
        accuracy = accuracy_score(labels, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average='weighted')
        
        return {
            'accuracy': accuracy,
            'f1': f1,
            'precision': precision,
            'recall': recall
        }
    
    def evaluate_model(self, texts: List[str], labels: List[int], task_type: str):
        """Evaluate trained model on test data."""
        if self.model is None or self.tokenizer is None:
            raise ValueError("Model not trained yet")
        
        # Create test dataset
        test_dataset = CybersecurityDataset(
            texts, labels, self.tokenizer, self.config.max_length
        )
        
        # Evaluate
        eval_result = self.trainer.evaluate(test_dataset)
        
        # Generate predictions for confusion matrix
        predictions = self.trainer.predict(test_dataset)
        y_pred = np.argmax(predictions.predictions, axis=1)
        
        # Create confusion matrix
        cm = confusion_matrix(labels, y_pred)
        
        # Plot confusion matrix
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title(f'Confusion Matrix - {task_type}')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig(self.output_dir / f"{task_type}_confusion_matrix.png")
        plt.close()
        
        return eval_result, cm

def main():
    """Main training function."""
    logger.info("Starting Cybersecurity Model Training")
    
    # Training configuration
    config = TrainingConfig(
        model_name="distilbert-base-uncased",
        batch_size=8,  # Smaller batch size for stability
        num_epochs=2,  # Fewer epochs for demo
        learning_rate=2e-5
    )
    
    # Initialize trainer
    trainer = CybersecurityModelTrainer(config)
    
    # Data path
    data_path = Path("data")
    
    # Train models for different tasks
    tasks = ["threat_detection", "log_classification", "vulnerability_severity"]
    training_results = {}
    
    for task in tasks:
        try:
            logger.info(f"Training model for {task}")
            
            # Load and prepare data
            texts, labels = trainer.load_and_prepare_data(str(data_path), task)
            
            if len(texts) == 0:
                logger.warning(f"No data available for {task}, skipping...")
                continue
            
            # Train model
            result = trainer.train_model(texts, labels, task)
            training_results[task] = result
            
            logger.info(f"Completed training for {task}")
            
        except Exception as e:
            logger.error(f"Training failed for {task}: {e}")
            training_results[task] = {"status": "failed", "error": str(e)}
    
    # Save overall training summary
    summary = {
        "timestamp": pd.Timestamp.now().isoformat(),
        "config": config.__dict__,
        "results": training_results
    }
    
    with open(Path(config.output_dir) / "training_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info("Training pipeline completed")
    
    # Display results
    print("\n" + "="*60)
    print("CYBERSECURITY MODEL TRAINING RESULTS")
    print("="*60)
    
    for task, result in training_results.items():
        if "status" in result and result["status"] == "failed":
            print(f"\n{task.upper()}: FAILED")
            print(f"  Error: {result['error']}")
        else:
            print(f"\n{task.upper()}: SUCCESS")
            print(f"  Training Loss: {result.get('training_loss', 'N/A'):.4f}")
            print(f"  Validation Loss: {result.get('eval_loss', 'N/A'):.4f}")
            print(f"  Accuracy: {result.get('eval_accuracy', 'N/A'):.4f}")
            print(f"  Samples: {result.get('train_samples', 0)} train, {result.get('val_samples', 0)} val")

if __name__ == "__main__":
    main()