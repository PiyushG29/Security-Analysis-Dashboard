"""
Anomaly Detector Module for the ASC System

This module implements advanced anomaly detection using machine learning algorithms
to identify unusual patterns in network traffic and system behavior.
"""

import time
import queue
import numpy as np
from typing import Dict, Any, List, Optional, Union
from collections import deque
import threading

from .base_detector import BaseDetector
from .network_traffic_detector import NetworkTrafficDetector
from src.ml.anomaly_model import AnomalyModel


class AnomalyDetector(BaseDetector):
    """
    Detector for identifying anomalous patterns in network traffic and system behavior.
    
    This detector uses:
    - Statistical analysis for initial anomaly detection
    - Machine learning models for pattern recognition
    - Behavioral profiling to establish baselines
    - Time-series analysis for trend detection
    """
    
    def __init__(self, event_queue: queue.Queue, config: Dict[str, Any] = None):
        """
        Initialize the anomaly detector.
        
        Args:
            event_queue: Queue for detected security events
            config: Configuration parameters
        """
        super().__init__(event_queue, config)
        
        # Configuration settings
        self.detection_window = self.config.get('detection_window', 300)  # 5 minutes
        self.analysis_interval = self.config.get('analysis_interval', 10)  # seconds
        self.sensitivity = self.config.get('sensitivity', 2.5)  # Standard deviations from mean
        self.learning_rate = self.config.get('learning_rate', 0.05)
        self.min_samples = self.config.get('min_samples', 100)
        self.use_ml = self.config.get('use_ml', True)
        
        # Data structures for analysis
        self.detection_history = deque(maxlen=int(self.detection_window / self.analysis_interval))
        self.feature_history = {}
        self.baselines = {}
        self.anomaly_scores = {}
        
        # Network traffic detector reference
        self.network_detector = None
        
        # Feature extraction configuration
        self.features = {
            'network': [
                'packet_rate',
                'connection_rate',
                'new_ip_rate',
                'protocol_distribution',
                'packet_size_distribution',
                'geographic_distribution'
            ],
            'flow': [
                'flow_duration',
                'packets_per_flow',
                'bytes_per_flow',
                'packet_inter_arrival'
            ],
            'behavior': [
                'connection_patterns',
                'periodic_activity',
                'data_transfer_patterns'
            ]
        }
        
        # Last analysis time
        self.last_analysis = time.time()
        
        # Anomaly detection models
        self.models = {}
        
        # Initialization flag
        self.initialized = False
        
        self.logger.info("Anomaly Detector initialized")
    
    def on_start(self):
        """Initialize resources when starting the detector."""
        # Find the network traffic detector
        self._find_network_detector()
        
        # Initialize models if using ML
        if self.use_ml:
            self._initialize_models()
            
        self.initialized = True
    
    def _find_network_detector(self):
        """Find the network traffic detector to access packet data."""
        try:
            # We'll look for the network detector in the security engine
            # This is a simplification - in a real implementation, we'd use a proper
            # service discovery or dependency injection mechanism
            
            # For now, we'll assume it's accessible by checking for a global engine instance
            # This would be replaced with proper component registration in production
            import sys
            if 'engine' in sys.modules['__main__'].__dict__:
                engine = sys.modules['__main__'].__dict__['engine']
                if hasattr(engine, 'detectors') and 'network' in engine.detectors:
                    self.network_detector = engine.detectors['network']
                    self.logger.info("Found network traffic detector")
        except Exception as e:
            self.logger.error(f"Error finding network detector: {e}")
    
    def _initialize_models(self):
        """Initialize the anomaly detection models."""
        try:
            from ..ml import model_manager
            
            # In a real implementation, we would load pre-trained models or create new ones
            # For simplicity, we'll just create placeholders
            self.models['statistical'] = {
                'name': 'StatisticalAnomalyModel',
                'type': 'statistical',
                'thresholds': {
                    feature: {'mean': 0, 'std': 1} for feature in self.features['network']
                }
            }
            
            if self.use_ml:
                try:
                    # Try to import required ML libraries
                    import numpy as np
                    from sklearn.ensemble import IsolationForest
                    from sklearn.svm import OneClassSVM
                    
                    # Create isolation forest model
                    self.models['isolation_forest'] = {
                        'name': 'IsolationForest',
                        'type': 'ml',
                        'model': IsolationForest(
                            contamination=0.01,  # Expected percentage of anomalies
                            n_estimators=100,
                            random_state=42
                        ),
                        'trained': False
                    }
                    
                    # Create one-class SVM model
                    self.models['one_class_svm'] = {
                        'name': 'OneClassSVM',
                        'type': 'ml',
                        'model': OneClassSVM(
                            nu=0.01,  # Expected percentage of anomalies
                            kernel='rbf'
                        ),
                        'trained': False
                    }
                    
                    self.logger.info("ML models initialized")
                    
                except ImportError:
                    self.logger.warning("Required ML libraries not available. Using statistical models only.")
                    self.use_ml = False
            
        except Exception as e:
            self.logger.error(f"Error initializing anomaly detection models: {e}", exc_info=True)
            self.use_ml = False
    
    def detect(self) -> Optional[List[Dict[str, Any]]]:
        """
        Detect anomalies in network traffic and system behavior.
        
        Returns:
            A list of security events if anomalies are detected
        """
        if not self.initialized:
            return None
            
        current_time = time.time()
        
        # Check if it's time to perform analysis
        if current_time - self.last_analysis < self.analysis_interval:
            return None
            
        self.last_analysis = current_time
        
        # Extract features for analysis
        features = self._extract_features()
        
        # No features to analyze
        if not features:
            return None
            
        # Update history and baselines
        self._update_history(features)
        
        # Perform anomaly detection
        anomalies = self._detect_anomalies(features)
        
        # Generate events for detected anomalies
        events = self._generate_events(anomalies) if anomalies else None
        
        return events
    
    def _extract_features(self) -> Dict[str, Any]:
        """
        Extract features from network traffic and system data.
        
        Returns:
            A dictionary of features for anomaly detection
        """
        features = {}
        
        # Get network statistics if network detector is available
        if self.network_detector:
            try:
                network_stats = self.network_detector.get_stats()
                
                # Basic network features
                features['packet_rate'] = network_stats.get('packet_rate', 0)
                features['active_connections'] = network_stats.get('active_connections', 0)
                features['unique_ips'] = network_stats.get('unique_ips', 0)
                
                # Protocol distribution
                protocols = network_stats.get('protocols', {})
                total_packets = sum(protocols.values()) if protocols else 1
                
                if total_packets > 0:
                    features['protocol_distribution'] = {
                        proto: count / total_packets for proto, count in protocols.items()
                    }
                    
                    # Calculate entropy of protocol distribution as a feature
                    entropy = 0
                    for proto, prob in features['protocol_distribution'].items():
                        if prob > 0:
                            entropy -= prob * np.log2(prob)
                            
                    features['protocol_entropy'] = entropy
                    
                # Get packet buffer for more detailed analysis
                packet_buffer = self.network_detector.get_packet_buffer()
                
                if packet_buffer:
                    # Analysis based on packet capture library
                    if hasattr(self.network_detector, 'capture_method'):
                        if self.network_detector.capture_method == 'pyshark':
                            self._analyze_pyshark_packets(packet_buffer, features)
                        elif self.network_detector.capture_method == 'scapy':
                            self._analyze_scapy_packets(packet_buffer, features)
                
            except Exception as e:
                self.logger.error(f"Error extracting network features: {e}")
        
        # Add timestamp
        features['timestamp'] = time.time()
        
        return features
    
    def _analyze_pyshark_packets(self, packets, features):
        """
        Analyze PyShark packets to extract additional features.
        
        Args:
            packets: List of PyShark packets
            features: Features dictionary to update
        """
        packet_sizes = []
        tcp_flags = {
            'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0,
            'syn_ack': 0, 'fin_ack': 0, 'rst_ack': 0
        }
        
        for packet in packets:
            # Extract packet size
            if hasattr(packet, 'length'):
                packet_sizes.append(int(packet.length))
                
            # Extract TCP flags
            if hasattr(packet, 'tcp'):
                flags = packet.tcp.flags
                
                if hasattr(flags, 'syn') and int(flags.syn) == 1:
                    if hasattr(flags, 'ack') and int(flags.ack) == 1:
                        tcp_flags['syn_ack'] += 1
                    else:
                        tcp_flags['syn'] += 1
                        
                if hasattr(flags, 'fin') and int(flags.fin) == 1:
                    if hasattr(flags, 'ack') and int(flags.ack) == 1:
                        tcp_flags['fin_ack'] += 1
                    else:
                        tcp_flags['fin'] += 1
                        
                if hasattr(flags, 'reset') and int(flags.reset) == 1:
                    if hasattr(flags, 'ack') and int(flags.ack) == 1:
                        tcp_flags['rst_ack'] += 1
                    else:
                        tcp_flags['rst'] += 1
        
        # Packet size statistics
        if packet_sizes:
            features['avg_packet_size'] = sum(packet_sizes) / len(packet_sizes)
            features['min_packet_size'] = min(packet_sizes)
            features['max_packet_size'] = max(packet_sizes)
            features['packet_size_std'] = np.std(packet_sizes) if len(packet_sizes) > 1 else 0
        
        # TCP flag statistics
        features['tcp_flags'] = tcp_flags
        
        # Connection attempts ratio (SYNs / total packets)
        total_packets = len(packets)
        if total_packets > 0:
            features['syn_ratio'] = tcp_flags['syn'] / total_packets
            features['rst_ratio'] = (tcp_flags['rst'] + tcp_flags['rst_ack']) / total_packets
    
    def _analyze_scapy_packets(self, packets, features):
        """
        Analyze Scapy packets to extract additional features.
        
        Args:
            packets: List of Scapy packets
            features: Features dictionary to update
        """
        from scapy.all import IP, TCP, UDP
        
        packet_sizes = []
        tcp_flags = {
            'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0,
            'syn_ack': 0, 'fin_ack': 0, 'rst_ack': 0
        }
        
        for packet in packets:
            # Extract packet size
            if hasattr(packet, 'len'):
                packet_sizes.append(packet.len)
                
            # Extract TCP flags
            if TCP in packet:
                tcp = packet[TCP]
                
                if tcp.flags & 0x02:  # SYN
                    if tcp.flags & 0x10:  # ACK
                        tcp_flags['syn_ack'] += 1
                    else:
                        tcp_flags['syn'] += 1
                        
                if tcp.flags & 0x01:  # FIN
                    if tcp.flags & 0x10:  # ACK
                        tcp_flags['fin_ack'] += 1
                    else:
                        tcp_flags['fin'] += 1
                        
                if tcp.flags & 0x04:  # RST
                    if tcp.flags & 0x10:  # ACK
                        tcp_flags['rst_ack'] += 1
                    else:
                        tcp_flags['rst'] += 1
        
        # Packet size statistics
        if packet_sizes:
            features['avg_packet_size'] = sum(packet_sizes) / len(packet_sizes)
            features['min_packet_size'] = min(packet_sizes)
            features['max_packet_size'] = max(packet_sizes)
            features['packet_size_std'] = np.std(packet_sizes) if len(packet_sizes) > 1 else 0
        
        # TCP flag statistics
        features['tcp_flags'] = tcp_flags
        
        # Connection attempts ratio (SYNs / total packets)
        total_packets = len(packets)
        if total_packets > 0:
            features['syn_ratio'] = tcp_flags['syn'] / total_packets
            features['rst_ratio'] = (tcp_flags['rst'] + tcp_flags['rst_ack']) / total_packets
    
    def _update_history(self, features: Dict[str, Any]) -> None:
        """
        Update the feature history and baselines.
        
        Args:
            features: The current feature values
        """
        # Add to detection history
        self.detection_history.append(features)
        
        # Update feature-specific history
        for feature, value in features.items():
            # Skip complex or non-numeric features
            if isinstance(value, (dict, list)) or feature == 'timestamp':
                continue
                
            if feature not in self.feature_history:
                self.feature_history[feature] = deque(maxlen=self.min_samples * 2)
                
            self.feature_history[feature].append(value)
            
            # Update baseline if we have enough samples
            if len(self.feature_history[feature]) >= self.min_samples:
                self._update_baseline(feature)
    
    def _update_baseline(self, feature: str) -> None:
        """
        Update the baseline for a specific feature.
        
        Args:
            feature: The feature to update
        """
        values = list(self.feature_history[feature])
        
        # Calculate baseline statistics
        mean = np.mean(values)
        std = np.std(values) if len(values) > 1 else 1.0
        
        # Update baseline with exponential moving average
        if feature in self.baselines:
            old_mean = self.baselines[feature]['mean']
            old_std = self.baselines[feature]['std']
            
            # Apply learning rate to update
            mean = (1 - self.learning_rate) * old_mean + self.learning_rate * mean
            std = (1 - self.learning_rate) * old_std + self.learning_rate * std
            
        # Create or update baseline entry
        self.baselines[feature] = {
            'mean': mean,
            'std': max(std, 0.0001),  # Avoid division by zero
            'min': np.min(values),
            'max': np.max(values),
            'last_update': time.time()
        }
    
    def _detect_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies in the current features.
        
        Args:
            features: The current feature values
            
        Returns:
            Dictionary of detected anomalies
        """
        anomalies = {}
        
        # Apply statistical detection first
        statistical_anomalies = self._detect_statistical_anomalies(features)
        if statistical_anomalies:
            anomalies.update(statistical_anomalies)
        
        # Apply ML-based detection if enabled and we have enough data
        if self.use_ml and len(self.detection_history) >= self.min_samples:
            ml_anomalies = self._detect_ml_anomalies(features)
            if ml_anomalies:
                anomalies.update(ml_anomalies)
        
        return anomalies
    
    def _detect_statistical_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect statistical anomalies in features.
        
        Args:
            features: The current feature values
            
        Returns:
            Dictionary of statistical anomalies
        """
        anomalies = {}
        
        # Check each numeric feature against its baseline
        for feature, value in features.items():
            # Skip complex or non-numeric features
            if isinstance(value, (dict, list)) or feature == 'timestamp':
                continue
                
            # Skip features without established baselines
            if feature not in self.baselines:
                continue
                
            baseline = self.baselines[feature]
            
            # Calculate z-score
            z_score = abs(value - baseline['mean']) / baseline['std']
            
            # Record anomaly score
            self.anomaly_scores[feature] = z_score
            
            # Check if the value is anomalous
            if z_score > self.sensitivity:
                anomalies[feature] = {
                    'value': value,
                    'baseline_mean': baseline['mean'],
                    'baseline_std': baseline['std'],
                    'z_score': z_score,
                    'type': 'statistical'
                }
        
        # Special checks for ratios and distributions
        if 'syn_ratio' in features and features['syn_ratio'] > 0.5:
            # High SYN ratio indicates possible SYN flood
            anomalies['high_syn_ratio'] = {
                'value': features['syn_ratio'],
                'threshold': 0.5,
                'type': 'signature',
                'category': 'dos'
            }
            
        if 'rst_ratio' in features and features['rst_ratio'] > 0.3:
            # High RST ratio indicates possible port scan
            anomalies['high_rst_ratio'] = {
                'value': features['rst_ratio'],
                'threshold': 0.3,
                'type': 'signature',
                'category': 'scan'
            }
            
        if 'protocol_entropy' in features:
            # Check if protocol entropy is abnormal
            if feature in self.baselines:
                baseline = self.baselines['protocol_entropy']
                if features['protocol_entropy'] < baseline['mean'] - self.sensitivity * baseline['std']:
                    # Abnormally low entropy indicates traffic concentration on few protocols
                    anomalies['low_protocol_entropy'] = {
                        'value': features['protocol_entropy'],
                        'baseline_mean': baseline['mean'],
                        'baseline_std': baseline['std'],
                        'type': 'statistical',
                        'category': 'traffic_focus'
                    }
        
        return anomalies
    
    def _detect_ml_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect ML-based anomalies.
        
        Args:
            features: The current feature values
            
        Returns:
            Dictionary of ML-detected anomalies
        """
        anomalies = {}
        
        # Extract numeric features for ML models
        feature_vector = self._extract_feature_vector(features)
        
        # Skip if feature vector couldn't be created
        if feature_vector is None or len(feature_vector) < 2:
            return anomalies
            
        feature_vector = np.array(feature_vector).reshape(1, -1)
        
        # Apply each ML model
        for model_name, model_info in self.models.items():
            if model_info['type'] != 'ml':
                continue
                
            # Skip untrained models or ensure they're trained
            if not model_info.get('trained', False):
                if not self._train_model(model_name):
                    continue
            
            try:
                # Make prediction
                model = model_info['model']
                result = model.predict(feature_vector)[0]
                
                # For isolation forest, -1 is anomaly, 1 is normal
                # For One-Class SVM, -1 is anomaly, 1 is normal
                if result == -1:
                    # Get anomaly score if available
                    score = None
                    if hasattr(model, 'score_samples'):
                        score = model.score_samples(feature_vector)[0]
                    
                    anomalies[f'ml_{model_name}'] = {
                        'type': 'ml',
                        'model': model_name,
                        'score': score,
                        'features_used': len(feature_vector[0])
                    }
            except Exception as e:
                self.logger.error(f"Error applying ML model {model_name}: {e}")
                
        return anomalies
    
    def _extract_feature_vector(self, features: Dict[str, Any]) -> Optional[List[float]]:
        """
        Extract a numeric feature vector from features for ML processing.
        
        Args:
            features: The feature dictionary
            
        Returns:
            A list of numeric features or None if not enough features
        """
        vector = []
        
        # Extract numeric features
        for feature, value in features.items():
            if isinstance(value, (int, float)) and feature != 'timestamp':
                vector.append(value)
                
        if len(vector) < 2:
            return None
            
        return vector
    
    def _train_model(self, model_name: str) -> bool:
        """
        Train an ML model using historical data.
        
        Args:
            model_name: Name of the model to train
            
        Returns:
            True if training was successful
        """
        if model_name not in self.models or self.models[model_name]['type'] != 'ml':
            return False
            
        # Check if we have enough data
        if len(self.detection_history) < self.min_samples:
            return False
            
        try:
            # Prepare training data
            X = []
            for historical_features in self.detection_history:
                feature_vector = self._extract_feature_vector(historical_features)
                if feature_vector is not None:
                    X.append(feature_vector)
            
            if len(X) < self.min_samples:
                return False
                
            X = np.array(X)
            
            # Train the model
            model = self.models[model_name]['model']
            model.fit(X)
            
            self.models[model_name]['trained'] = True
            self.logger.info(f"Trained ML model {model_name} with {len(X)} samples")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training model {model_name}: {e}")
            return False
    
    def _generate_events(self, anomalies: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate security events from detected anomalies.
        
        Args:
            anomalies: Dictionary of detected anomalies
            
        Returns:
            List of security events
        """
        events = []
        
        # Group anomalies by type and calculate overall score
        statistical_anomalies = {k: v for k, v in anomalies.items() 
                               if v.get('type') == 'statistical'}
        ml_anomalies = {k: v for k, v in anomalies.items() 
                       if v.get('type') == 'ml'}
        signature_anomalies = {k: v for k, v in anomalies.items() 
                             if v.get('type') == 'signature'}
        
        # Generate events based on anomaly type
        if statistical_anomalies:
            # Get total z-score and maximum z-score
            z_scores = [a['z_score'] for a in statistical_anomalies.values() 
                       if 'z_score' in a]
            
            if z_scores:
                total_z_score = sum(z_scores)
                max_z_score = max(z_scores)
                
                # Determine severity based on z-scores
                severity = 1
                if max_z_score > self.sensitivity * 2:
                    severity = 4
                elif max_z_score > self.sensitivity * 1.5:
                    severity = 3
                elif max_z_score > self.sensitivity:
                    severity = 2
                
                # Calculate score as percentage of max (100)
                score = min(int(40 + 60 * (max_z_score / (self.sensitivity * 3))), 100)
                
                # Create event
                events.append({
                    'name': 'Statistical Anomaly Detected',
                    'type': 'anomaly.statistical',
                    'severity': severity,
                    'score': score,
                    'details': {
                        'anomalous_features': list(statistical_anomalies.keys()),
                        'max_z_score': max_z_score,
                        'total_z_score': total_z_score,
                        'anomaly_count': len(statistical_anomalies)
                    }
                })
        
        if ml_anomalies:
            # Determine severity based on model confidence
            severity = 2  # Default for ML anomalies
            
            # Calculate score based on number of models that detected anomalies
            score = min(int(50 + 50 * (len(ml_anomalies) / len([m for m in self.models 
                                                              if m.get('type') == 'ml']))), 100)
            
            # Create event
            events.append({
                'name': 'Machine Learning Anomaly Detected',
                'type': 'anomaly.ml',
                'severity': severity,
                'score': score,
                'details': {
                    'models': [a.get('model', 'unknown') for a in ml_anomalies.values()],
                    'scores': [a.get('score', None) for a in ml_anomalies.values() 
                             if a.get('score') is not None],
                    'anomaly_count': len(ml_anomalies)
                }
            })
        
        if signature_anomalies:
            for name, anomaly in signature_anomalies.items():
                # Determine severity and score based on anomaly category
                severity = 3  # Default
                score = 75    # Default
                
                if anomaly.get('category') == 'dos':
                    severity = 4
                    score = 90
                elif anomaly.get('category') == 'scan':
                    severity = 3
                    score = 80
                
                # Create event
                events.append({
                    'name': f'Signature-Based Anomaly: {name}',
                    'type': f"anomaly.signature.{anomaly.get('category', 'unknown')}",
                    'severity': severity,
                    'score': score,
                    'details': {
                        'value': anomaly.get('value'),
                        'threshold': anomaly.get('threshold'),
                        'category': anomaly.get('category', 'unknown')
                    }
                })
        
        return events