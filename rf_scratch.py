import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split 


class StandardScaler:
    def __init__(self):
        self.mean = None
        self.std = None

    
    def fit(self, X):
        X = np.array(X)

        self.mean = np.mean(X, axis=0)
        self.std = np.std(X, axis=0)

        self.std = np.where(self.std==0,1,self.std)
        return self

    def transform(self,X):
        if self.mean is None or self.std is None:
            raise ValueError("scaler must be fitted prior to transforming")
        
        X = np.array(X)
        return (X-self.mean)/self.std
    
    def fit_transform(self,X):
        return self.fit(X).transform(X)
                


class DecisionTree:
    def __init__(self, max_depth=10, min_samples_split=2):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.tree = None
    
    def entropy(self, y):
        m = len(y)
        if m == 0:
            return 0
        counts = np.bincount(y)
        # Convert to probabilities
        probs = counts / m
        entropy_val = -np.sum([p * np.log2(p) for p in probs if p > 0])
        return entropy_val
    
    def information_gain(self, parent, left_y, right_y):
        parent_entropy = self.entropy(parent)
        n = len(parent)
        n_l, n_r = len(left_y), len(right_y)

        if n_l == 0 or n_r == 0:
            return 0
        child_entropy = (n_l / n) * self.entropy(left_y) + (n_r / n) * self.entropy(right_y)
        return parent_entropy - child_entropy
    
    def best_split(self, X, y):
        best_gain = -1
        split_i, split_thresh = None, None

        n_features = X.shape[1]
        feature_indices = np.random.choice(n_features,int(np.sqrt(n_features)),replace=False)

        for feat_i in feature_indices:
            thresholds = np.unique(X[:, feat_i])
            for threshold in thresholds:
                left = X[:, feat_i] <= threshold
                right = ~left

                if not any(left) or not any(right):
                    continue
                current_gain = self.information_gain(y,y[left],y[right])

                if current_gain > best_gain:
                    best_gain = current_gain
                    split_i = feat_i
                    split_thresh = threshold
            return split_i, split_thresh
        

    def build_tree(self, X, y, depth=0):
        num_samples, num_features = X.shape
        # Stop if max depth reached or samples too small
        if depth >= self.max_depth or num_samples < self.min_samples_split or len(np.unique(y)) == 1:
            leaf_value = self.most_common_label(y)
            return {'leaf': leaf_value}

        idx, thresh = self.best_split(X, y)
        if idx is None:
            return {'leaf': self.most_common_label(y)}

        left_idx = np.where(X[:, idx] <= thresh)[0]
        right_idx = np.where(X[:, idx] > thresh)[0]

        left_subtree = self.build_tree(X[left_idx], y[left_idx], depth + 1)
        right_subtree = self.build_tree(X[right_idx], y[right_idx], depth + 1)

        return {'idx': idx, 'thresh': thresh, 'left': left_subtree, 'right': right_subtree}

    def most_common_label(self, y):
        return np.bincount(y).argmax()

    def fit(self, X, y):
        self.tree = self.build_tree(X, y)

    def predict_row(self, row, tree):
        if 'leaf' in tree:
            return tree['leaf']
        if row[tree['idx']] <= tree['thresh']:
            return self.predict_row(row, tree['left'])
        return self.predict_row(row, tree['right'])

    def predict(self, X):
        return np.array([self.predict_row(row, self.tree) for row in X])





class RandomForest:
    def __init__(self, n_trees=10, max_depth=5, min_samples_split=2):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.trees = []

    def _bootstrap_sample(self, X, y):
        n_samples = X.shape[0]
        indices = np.random.choice(n_samples, n_samples, replace=True)
        return X[indices], y[indices]

    def fit(self, X, y):
        X = np.array(X)
        y = np.array(y)
        self.trees = []
        for _ in range(self.n_trees):
            tree = DecisionTree(max_depth=self.max_depth, min_samples_split=self.min_samples_split)
            X_sample, y_sample = self._bootstrap_sample(X, y)
            tree.fit(X_sample, y_sample)
            self.trees.append(tree)

    def predict(self, X):
        tree_preds = np.array([tree.predict(X) for tree in self.trees])
        
        tree_preds = tree_preds.T
        
        final_preds = []
        for row in tree_preds:
            final_preds.append(np.bincount(row).argmax())
        
        return np.array(final_preds)
    
class MLfuncs:
    def __init__(self):
        pass
        
    def accuracy_score(self,y_true, y_pred):
        return np.sum(y_true == y_pred) / len(y_true)

    def classification_report(self,y_true, y_pred):
        """
        Generates a text report showing the main classification metrics.
        Works for multi-class classification.
        """
        labels = np.unique(y_true)
        report = "Class | Precision | Recall | F1-Score | Support\n"
        report += "-" * 50 + "\n"
        
        for label in labels:
            tp = np.sum((y_true == label) & (y_pred == label))
            fp = np.sum((y_true != label) & (y_pred == label))
            fn = np.sum((y_true == label) & (y_pred != label))
            support = np.sum(y_true == label)
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            report += f"{label:>5} | {precision:>9.2f} | {recall:>6.2f} | {f1:>8.2f} | {support:>7}\n"
        
        acc = self.accuracy_score(y_true, y_pred)
        report += "-" * 50 + "\n"
        report += f"Accuracy: {acc:.2f}"
        
        return report
    
    def find_k_nearest_neighbors(self,X_minority, sample_row, k):
        """Finds the k closest minority samples using Euclidean distance."""
        # Vectorized Euclidean distance calculation
        distances = np.linalg.norm(X_minority - sample_row, axis=1)
        # Get indices of the k smallest distances (excluding the sample itself at index 0)
        neighbor_indices = np.argsort(distances)[1:k+1]
        return X_minority[neighbor_indices]

    def generate_synthetic_sample(self,sample_row, neighbors):
        """Creates a new sample by interpolating between a row and a random neighbor."""
        # Pick one neighbor at random from the k-neighbors provided
        neighbor = neighbors[np.random.randint(len(neighbors))]
        
        # Standard SMOTE formula: Sample + rand * (Neighbor - Sample)
        diff = neighbor - sample_row
        random_factor = np.random.uniform(0, 1)
        
        return sample_row + (diff * random_factor)

    def apply_smote(self,X, y, target_ratio=1.0, k=5):
        """Main function to balance the dataset."""
        unique, counts = np.unique(y, return_counts=True)
        minority_class = unique[np.argmin(counts)]
        majority_class = unique[np.argmax(counts)]
        
        X_min = X[y == minority_class]
        n_majority = counts[np.argmax(counts)]
        n_minority = len(X_min)
        
        n_target = int(n_majority * target_ratio)
        n_to_generate = n_target - n_minority
        
        if n_to_generate <= 0:
            return X, y

        synthetic_samples = []
        
        for _ in range(n_to_generate):
            idx = np.random.randint(0, n_minority)
            sample_row = X_min[idx]
            
            neighbors = self.find_k_nearest_neighbors(X_min, sample_row, k)
            
            new_row = self.generate_synthetic_sample(sample_row, neighbors)
            synthetic_samples.append(new_row)
        
        X_synthetic = np.array(synthetic_samples)
        y_synthetic = np.full(len(X_synthetic), minority_class)
        
        X_balanced = np.vstack((X, X_synthetic))
        y_balanced = np.concatenate((y, y_synthetic))
        
        return X_balanced, y_balanced
    
def main():
    np.random.seed(42)
    df = pd.read_csv("port_scan_dataset.csv")
    X = df.drop('Label',axis=1)
    y = df['Label']
    df = pd.get_dummies(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    mr = MLfuncs()

    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    X_bal, y_bal = mr.apply_smote(X_train_scaled, y_train)
    indices = np.arange(len(X_bal))
    np.random.shuffle(indices)

    X_bal = X_bal[indices]
    y_bal = y_bal[indices]


    rf = RandomForest(n_trees=65,max_depth=8,min_samples_split=2)
    rf.fit(X_bal, y_bal)

    y_pred = rf.predict(X_test_scaled)
    print("Accuracy:", mr.accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(mr.classification_report(y_test, y_pred))

if __name__ == "__main__":
    main()