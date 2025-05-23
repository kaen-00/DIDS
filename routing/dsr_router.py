### dsr_router.py

# Simulated DSR-based rerouting logic for IoT intrusion scenarios
# In a real network, this would interface with actual routing tables or software-defined network controllers

NETWORK_GRAPH = {
    "pi": ["laptop_b", "laptop_a"],
    "laptop_b": ["pi", "laptop_a"],
    "laptop_a": ["pi", "laptop_b"]
}

def find_secure_path(source, destination, trust_scores):
    """
    Find a secure path using DSR principles (avoid low-trust nodes)
    trust_scores: {"node": trust_value}
    """
    def dfs(current, target, path, visited):
        if current == target:
            return path

        visited.add(current)
        for neighbor in NETWORK_GRAPH.get(current, []):
            if neighbor not in visited and trust_scores.get(neighbor, 100) >= 70:
                result = dfs(neighbor, target, path + [neighbor], visited)
                if result:
                    return result
        return None

    return dfs(source, destination, [source], set())

# Example usage
if __name__ == "__main__":
    trust_scores = {
        "pi": 50,
        "laptop_b": 80,
        "laptop_a": 100
    }
    path = find_secure_path("pi", "laptop_a", trust_scores)
    print("Secure path:", path if path else "No secure path found")