from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import json
import os
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict

# Set up logging
logger = logging.getLogger('policy_store')

# Define the Policy DTO
@dataclass
class Policy:
    """Data Transfer Object for policy data."""
    policy_name: str
    policy_description: str
    policy_applicability: str  # "input", "output", or "both"
    policy_content: str
    active: bool = True
    
    @classmethod
    def from_db_document(cls, doc):
        """Create a Policy from a document."""
        return cls(
            policy_name=doc.get("_id"),
            policy_description=doc.get("description", ""),
            policy_applicability=doc.get("applicability", "both"),
            policy_content=doc.get("raw_content", ""),
            active=doc.get("active", True)
        )
    
    def to_dict(self):
        """Convert the Policy to a dictionary."""
        return asdict(self)
    
    def to_document(self):
        """Convert the Policy to a document for storage."""
        return {
            "_id": self.policy_name,
            "description": self.policy_description,
            "applicability": self.policy_applicability,
            "raw_content": self.policy_content,
            "active": self.active
        }

# Abstract Policy Data Store
class PolicyDataStore(ABC):
    """Abstract base class for policy data storage implementations."""
    
    @abstractmethod
    def get_policy(self, policy_name):
        """Get a policy by name."""
        pass
    
    @abstractmethod
    def get_all_policies(self, filters=None):
        """Get all policies, optionally filtered."""
        pass
    
    @abstractmethod
    def create_or_update_policy(self, policy):
        """Create or update a policy."""
        pass
    
    @abstractmethod
    def delete_policy(self, policy_name):
        """Delete a policy."""
        pass
    
    @abstractmethod
    def update_policy_status(self, policy_name, active):
        """Update a policy's active status."""
        pass
    
    @abstractmethod
    def get_active_policies(self):
        """Get all active policies."""
        pass
    
    @abstractmethod
    def is_available(self):
        """Check if the data store is available."""
        pass

# MongoDB Policy Data Store
class MongoDbPolicyDataStore(PolicyDataStore):
    """MongoDB implementation of PolicyDataStore."""
    
    def __init__(self, uri="mongodb+srv://Cluster92016:anZCQmFsT1JY@cluster92016.m58i198.mongodb.net/?retryWrites=true&w=majority&appName=Cluster92016"):
        """Initialize MongoDB connection."""
        self.uri = uri
        self.client = MongoClient(uri, server_api=ServerApi('1'))
        try:
            self.client.admin.command('ping')
            logger.info("Connected to MongoDB successfully!")
            self.db = self.client['policy']
            self.policy_collection = self.db['policies']
            self._available = True
        except Exception as e:
            logger.error(f"MongoDB connection error: {e}")
            self._available = False
    
    def is_available(self):
        """Check if MongoDB is available."""
        return self._available
    
    def get_policy(self, policy_name):
        """Get a policy by name from MongoDB."""
        if not self._available:
            raise Exception("MongoDB is not available")
        
        policy_doc = self.policy_collection.find_one({"_id": policy_name})
        if not policy_doc:
            return None
        
        return Policy.from_db_document(policy_doc)
    
    def get_all_policies(self, filters=None):
        """Get policies from MongoDB, with optional filters."""
        if not self._available:
            raise Exception("MongoDB is not available")
        
        query_filter = filters or {}
        policy_docs = self.policy_collection.find(query_filter)
        return [Policy.from_db_document(doc) for doc in policy_docs]
    
    def create_or_update_policy(self, policy):
        """Create or update a policy in MongoDB."""
        if not self._available:
            raise Exception("MongoDB is not available")
        
        policy_document = {
            "description": policy.policy_description,
            "applicability": policy.policy_applicability,
            "raw_content": policy.policy_content,
            "active": policy.active
        }
        
        result = self.policy_collection.update_one(
            {"_id": policy.policy_name},
            {"$set": policy_document},
            upsert=True
        )
        
        # Return whether this was an insert or update
        return bool(result.upserted_id)
    
    def delete_policy(self, policy_name):
        """Delete a policy from MongoDB."""
        if not self._available:
            raise Exception("MongoDB is not available")
        
        result = self.policy_collection.delete_one({"_id": policy_name})
        return result.deleted_count > 0
    
    def update_policy_status(self, policy_name, active):
        """Update policy status in MongoDB."""
        if not self._available:
            raise Exception("MongoDB is not available")
        
        result = self.policy_collection.update_one(
            {"_id": policy_name},
            {"$set": {"active": active}}
        )
        
        # Get the updated policy
        updated_policy_doc = self.policy_collection.find_one({"_id": policy_name})
        if not updated_policy_doc:
            return None
        
        return Policy.from_db_document(updated_policy_doc)
    
    def get_active_policies(self):
        """Get all active policies from MongoDB."""
        if not self._available:
            raise Exception("MongoDB is not available")
        
        return self.get_all_policies({"active": True})

# Local JSON File Policy Data Store
class LocalPolicyDataStore(PolicyDataStore):
    """JSON file implementation of PolicyDataStore."""
    
    def __init__(self, file_path="db.json"):
        """Initialize local JSON file storage."""
        self.file_path = file_path
        self._available = True
        
        # Create file if it doesn't exist
        if not os.path.exists(file_path):
            try:
                with open(file_path, 'w') as f:
                    json.dump([], f)
                logger.info(f"Created new policy file at {file_path}")
            except Exception as e:
                logger.error(f"Error creating policy file: {e}")
                self._available = False
    
    def is_available(self):
        """Check if local file storage is available."""
        return self._available and os.path.exists(self.file_path)
    
    def _read_policies(self):
        """Read all policies from the JSON file."""
        if not self.is_available():
            raise Exception(f"Policy file {self.file_path} is not available")
        
        try:
            with open(self.file_path, 'r') as f:
                policies_data = json.load(f)
            return policies_data
        except Exception as e:
            logger.error(f"Error reading policies from {self.file_path}: {e}")
            raise
    
    def _write_policies(self, policies_data):
        """Write policies to the JSON file."""
        if not self._available:
            raise Exception("Local file storage is not available")
        
        try:
            with open(self.file_path, 'w') as f:
                json.dump(policies_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error writing policies to {self.file_path}: {e}")
            raise
    
    def get_policy(self, policy_name):
        """Get a policy by name from the JSON file."""
        policies_data = self._read_policies()
        
        for policy_data in policies_data:
            if policy_data.get("_id") == policy_name:
                return Policy.from_db_document(policy_data)
        
        return None
    
    def get_all_policies(self, filters=None):
        """Get all policies from the JSON file, with optional filters."""
        policies_data = self._read_policies()
        filtered_policies = []
        
        # Apply filters if provided
        if filters:
            for policy_data in policies_data:
                match = True
                for key, value in filters.items():
                    # Handle special case for regex in MongoDB style
                    if isinstance(value, dict) and "$regex" in value:
                        import re
                        pattern = value["$regex"]
                        options = value.get("$options", "")
                        regex_flags = 0
                        if "i" in options:
                            regex_flags |= re.IGNORECASE
                        
                        field_value = policy_data.get(key, "")
                        if not re.search(pattern, field_value, regex_flags):
                            match = False
                            break
                    elif policy_data.get(key) != value:
                        match = False
                        break
                
                if match:
                    filtered_policies.append(policy_data)
        else:
            filtered_policies = policies_data
        
        return [Policy.from_db_document(doc) for doc in filtered_policies]
    
    def create_or_update_policy(self, policy):
        """Create or update a policy in the JSON file."""
        policies_data = self._read_policies()
        
        # Check if policy exists
        is_new = True
        policy_doc = policy.to_document()
        
        for i, existing_policy in enumerate(policies_data):
            if existing_policy.get("_id") == policy.policy_name:
                # Update existing policy
                policies_data[i] = policy_doc
                is_new = False
                break
        
        # Add new policy if not found
        if is_new:
            policies_data.append(policy_doc)
        
        # Write back to file
        self._write_policies(policies_data)
        return is_new
    
    def delete_policy(self, policy_name):
        """Delete a policy from the JSON file."""
        policies_data = self._read_policies()
        initial_count = len(policies_data)
        
        # Filter out the policy to delete
        policies_data = [p for p in policies_data if p.get("_id") != policy_name]
        
        # Write back to file
        self._write_policies(policies_data)
        return len(policies_data) < initial_count
    
    def update_policy_status(self, policy_name, active):
        """Update policy status in the JSON file."""
        policies_data = self._read_policies()
        updated_policy = None
        
        for i, policy_data in enumerate(policies_data):
            if policy_data.get("_id") == policy_name:
                policies_data[i]["active"] = active
                updated_policy = Policy.from_db_document(policies_data[i])
                break
        
        # Write back to file if updated
        if updated_policy:
            self._write_policies(policies_data)
        
        return updated_policy
    
    def get_active_policies(self):
        """Get all active policies from the JSON file."""
        return self.get_all_policies({"active": True}) 