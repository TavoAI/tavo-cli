from flask import Flask, request, jsonify
from opa_client import OpaClient  # from https://github.com/Turall/OPA-python-client
import subprocess
import time
import logging
import json
import os
import argparse
from policy_store import Policy, MongoDbPolicyDataStore, LocalPolicyDataStore

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('policy_server')

app = Flask(__name__)

# Initialize the OPA client
opa = OpaClient(host='localhost', port=8181)

# Global data store variable to be set during startup
policy_data_store = None

def sync_policies_to_opa():
    """Fetches all active policies from the data store and registers them with OPA."""
    logger.info("Syncing active policies to OPA...")
    
    try:
        if not policy_data_store.is_available():
            logger.error("Policy data store is not available. Cannot sync policies to OPA.")
            return
        
        # Get active policies from the data store
        active_policies = policy_data_store.get_active_policies()
        
        count = 0
        for policy in active_policies:
            if policy.policy_name and policy.policy_content:
                try:
                    opa.update_policy_from_string(policy.policy_content, policy.policy_name)
                    logger.info(f"  - Registered policy '{policy.policy_name}' with OPA.")
                    count += 1
                except Exception as opa_err:
                    logger.error(f"  - Error registering policy '{policy.policy_name}' with OPA: {opa_err}")
            else:
                logger.warning(f"  - Skipping policy with missing name or content: {policy.policy_name}")

        logger.info(f"Policy sync complete. {count} active policies registered with OPA.")

    except Exception as e:
        logger.error(f"Error syncing policies to OPA: {e}")

def start_opa_server():
    """Attempts to start the OPA server as a background process."""
    logger.info("Attempting to start OPA server...")
    try:
        # Start OPA server as a background process
        opa_process = subprocess.Popen(['opa', 'run', '--server'])
        logger.info(f"OPA server process started (PID: {opa_process.pid}). Waiting for it to initialize...")
        # Give OPA a couple of seconds to start up
        time.sleep(2)
        return True # Indicate success
    except FileNotFoundError:
        logger.error("Error: 'opa' command not found. Please ensure OPA is installed and in your PATH.")
    except Exception as e:
        logger.error(f"An error occurred while starting OPA: {e}")
    return False # Indicate failure

def load_prebuilt_policies(file_path="local_policies_export.json"):
    """Load prebuilt policies from a file into the policy data store."""
    if not os.path.exists(file_path):
        logger.error(f"Prebuilt policies file not found: {file_path}")
        return False
    
    try:
        with open(file_path, 'r') as f:
            prebuilt_policies = json.load(f)
        
        count = 0
        for policy_data in prebuilt_policies:
            policy = Policy.from_db_document(policy_data)
            policy_data_store.create_or_update_policy(policy)
            count += 1
        
        logger.info(f"Loaded {count} prebuilt policies into data store")
        return True
    except Exception as e:
        logger.error(f"Error loading prebuilt policies: {e}")
        return False

@app.route('/policies/<policy_name>', methods=['GET'])
def get_policy(policy_name):
    """
    Retrieves a policy by name.
    
    Args:
        policy_name: The name of the policy to retrieve
        
    Returns:
        JSON with the policy details or an error message
    """
    if not policy_data_store.is_available():
        return jsonify({"error": "Policy data store is not available."}), 503  # Service Unavailable
    
    if not policy_name:
        return jsonify({"error": "Policy name is required."}), 400
    
    try:
        # Find the policy in the data store
        policy = policy_data_store.get_policy(policy_name)
        
        if not policy:
            return jsonify({"error": f"Policy '{policy_name}' not found."}), 404
        
        return jsonify(policy.to_dict()), 200
    
    except Exception as e:
        logger.error(f"Error retrieving policy '{policy_name}': {e}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/policies', methods=['GET'])
def get_all_policies():
    """
    Retrieves all policies.
    
    Query parameters:
        domain: Optional filter for policies by domain
        applicability: Optional filter for policies by applicability (input/output/both)
    
    Returns:
        JSON with the list of policies or an error message
    """
    if not policy_data_store.is_available():
        return jsonify({"error": "Policy data store is not available."}), 503  # Service Unavailable
    
    try:
        # Get optional query parameters
        domain = request.args.get('domain')
        applicability = request.args.get('applicability')
        
        # Build the query filter
        query_filter = {}
        if domain:
            query_filter["_id"] = {"$regex": f"^{domain}_", "$options": "i"}
        if applicability:
            query_filter["applicability"] = applicability
        
        # Find matching policies in the data store
        policies = policy_data_store.get_all_policies(query_filter)
        
        # Convert to list of dicts for response
        policy_dicts = [policy.to_dict() for policy in policies]
        
        return jsonify({
            "count": len(policy_dicts),
            "policies": policy_dicts
        }), 200
    
    except Exception as e:
        logger.error(f"Error retrieving policies: {e}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/policies', methods=['POST'])
def create_policy():
    """
    Creates or updates a policy.
    
    Expected JSON:
    {
      "policy_name": "my_policy",
      "policy_description": "A brief description of the policy",
      "policy_applicability": "input",  # or "output", "both"
      "policy_content": "package myapp\\n ... rego code ...",
      "active": true                    # optional, defaults to true
    }
    
    Returns:
        201 Created on success with the policy details
    """
    if not policy_data_store.is_available():
        return jsonify({"error": "Policy data store is not available."}), 503 # Service Unavailable

    data = request.get_json()
    
    # Use the Policy DTO to validate the input
    try:
        policy = Policy(
            policy_name=data.get("policy_name"),
            policy_description=data.get("policy_description", ""),
            policy_applicability=data.get("policy_applicability", "both"),
            policy_content=data.get("policy_content", ""),
            active=data.get("active", True)
        )
    except TypeError as e:
        return jsonify({"error": f"Invalid policy data: {str(e)}"}), 400
        
    # Validate required fields
    if not policy.policy_name or not policy.policy_content:
        return jsonify({"error": "Missing required fields: 'policy_name' and 'policy_content' are required."}), 400
    
    # Validate policy_applicability value
    if policy.policy_applicability not in ["input", "output", "both"]:
        return jsonify({"error": "Field 'policy_applicability' must be one of 'input', 'output', or 'both'."}), 400

    try:
        # Only upload to OPA if the policy is active
        if policy.active:
            # 1. Upload the policy to OPA
            opa.update_policy_from_string(policy.policy_content, policy.policy_name)
            logger.info(f"Policy '{policy.policy_name}' registered with OPA.")
        else:
            logger.info(f"Policy '{policy.policy_name}' created as inactive, not registering with OPA.")

        # 2. Store policy in the data store
        is_new = policy_data_store.create_or_update_policy(policy)

    except Exception as e:
        logger.error(f"Error during policy creation or storage: {e}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

    # Determine response message based on whether it was inserted or modified
    db_message = "Policy created." if is_new else "Policy updated."
    status_code = 201 if is_new else 200  # 201 Created for new resources

    # Add activation status to the message
    activation_message = "" if policy.active else " Policy is currently inactive."
    logger.info(f"Policy '{policy.policy_name}' {db_message}{activation_message}")
    
    response = {
        "policy": policy.to_dict(),
        "message": f"Policy '{policy.policy_name}' successfully {db_message.lower()}{activation_message}"
    }
    
    return jsonify(response), status_code

@app.route('/policies/<policy_name>/evaluate', methods=['POST'])
def evaluate_policy(policy_name):
    """
    Evaluates input data against a specific policy.
    Only active policies can be evaluated.
    """
    if not policy_data_store.is_available():
        return jsonify({"error": "Policy data store is not available."}), 503
        
    data = request.get_json()
    input_data = data.get("input")
    
    if not policy_name:
        return jsonify({"error": "Policy name is required."}), 400
    
    if input_data is None:
        return jsonify({"error": "Missing 'input' in the request body."}), 400
    
    try:
        # Check if the policy exists and is active
        policy = policy_data_store.get_policy(policy_name)
        
        if not policy:
            return jsonify({"error": f"Policy '{policy_name}' not found."}), 404
            
        # Check if the policy is active
        if not policy.active:
            logger.warning(f"Attempted to evaluate inactive policy '{policy_name}'")
            return jsonify({
                "error": f"Policy '{policy_name}' is not active.",
                "allow": False,
                "rejection_reasons": ["Policy is inactive and cannot be evaluated."]
            }), 403  # Forbidden
        
        # Evaluate the input using the specified policy
        logger.info(f"Evaluating input against policy '{policy_name}'")
        allow = opa.check_permission(input_data, policy_name, "allow").get("result", False)
        rejection_reasons = opa.check_permission(input_data, policy_name, "rejection_reasons").get("result", [])

    except Exception as e:
        logger.error(f"Error evaluating policy '{policy_name}': {e}")
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "allow": allow,
        "rejection_reasons": rejection_reasons
    }), 200

@app.route('/policies/<policy_name>', methods=['DELETE'])
def delete_policy(policy_name):
    """
    Deletes a policy.
    
    Args:
        policy_name: The name of the policy to delete
        
    Returns:
        204 No Content on successful deletion
        404 Not Found if policy doesn't exist
    """
    if not policy_data_store.is_available():
        return jsonify({"error": "Policy data store is not available."}), 503  # Service Unavailable
    
    if not policy_name:
        return jsonify({"error": "Policy name is required."}), 400
    
    try:
        # Check if the policy exists in the data store
        policy = policy_data_store.get_policy(policy_name)
        if not policy:
            logger.info(f"Policy '{policy_name}' not found, cannot delete.")
            return jsonify({
                "error": f"Policy '{policy_name}' not found",
                "message": "The requested policy does not exist and therefore cannot be deleted."
            }), 404
            
        # Policy exists, proceed with deletion
        
        # 1. Delete the policy from OPA
        try:
            opa.delete_policy(policy_name)
            logger.info(f"Deleted policy '{policy_name}' from OPA.")
            opa_success = True
        except Exception as opa_err:
            logger.error(f"Error deleting policy '{policy_name}' from OPA: {opa_err}")
            opa_success = False
        
        # 2. Delete policy from the data store
        try:
            db_success = policy_data_store.delete_policy(policy_name)
            logger.info(f"Delete result: {'Success' if db_success else 'Failed'}")
        except Exception as db_err:
            logger.error(f"Error deleting policy '{policy_name}' from data store: {db_err}")
            db_success = False
        
        # 3. Prepare response
        if opa_success and db_success:
            # Return 204 No Content for successful deletion (REST best practice)
            return "", 204
        elif opa_success:
            message = f"Policy '{policy_name}' deleted from OPA but failed to delete from data store."
            status_code = 500  # Internal server error since we know it exists but failed to delete
        elif db_success:
            message = f"Policy '{policy_name}' deleted from data store but failed to delete from OPA."
            status_code = 207  # Partial success
        else:
            message = f"Failed to delete policy '{policy_name}' from OPA and data store."
            status_code = 500
        
        return jsonify({
            "opa_success": opa_success,
            "db_success": db_success,
            "message": message
        }), status_code
    
    except Exception as e:
        logger.error(f"Unexpected error deleting policy '{policy_name}': {e}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/policies', methods=['DELETE'])
def delete_policy_by_name_in_body():
    """
    Deletes a policy using the policy name specified in the request body.
    
    Expected JSON:
    {
      "policy_name": "my_policy"
    }
    
    Returns:
        204 No Content on successful deletion
        404 Not Found if policy doesn't exist
    """
    if not policy_data_store.is_available():
        return jsonify({"error": "Policy data store is not available."}), 503  # Service Unavailable
        
    data = request.get_json()
    policy_name = data.get("policy_name")
    
    if not policy_name:
        return jsonify({"error": "Missing 'policy_name' in the request body."}), 400
    
    # Call the existing handler function to handle the deletion logic
    return delete_policy(policy_name)

@app.route('/policies/<policy_name>/status', methods=['PUT'])
def update_policy_status(policy_name):
    """
    Activates or deactivates a policy.
    
    Args:
        policy_name: The name of the policy to update
        
    Expected JSON:
    {
      "active": true/false   # boolean indicating whether to activate or deactivate
    }
    
    Returns:
        JSON with updated policy details or an error message
    """
    if not policy_data_store.is_available():
        return jsonify({"error": "Policy data store is not available."}), 503
    
    if not policy_name:
        return jsonify({"error": "Policy name is required."}), 400
    
    data = request.get_json()
    active = data.get("active")
    
    if active is None:
        return jsonify({"error": "Missing 'active' field in request body."}), 400
    
    if not isinstance(active, bool):
        return jsonify({"error": "'active' field must be a boolean."}), 400
    
    try:
        # Check if the policy exists
        policy = policy_data_store.get_policy(policy_name)
        
        if not policy:
            return jsonify({"error": f"Policy '{policy_name}' not found."}), 404
        
        # Update the active status in the data store
        updated_policy = policy_data_store.update_policy_status(policy_name, active)
        
        if not updated_policy:
            return jsonify({"error": f"Failed to update status for policy '{policy_name}'"}), 500
        
        # Handle OPA activation/deactivation based on the active flag
        if active:
            # If activating, (re)register the policy with OPA
            if updated_policy.policy_content:
                opa.update_policy_from_string(updated_policy.policy_content, policy_name)
                logger.info(f"Policy '{policy_name}' activated and registered with OPA.")
            else:
                logger.error(f"Policy '{policy_name}' has no content, cannot register with OPA.")
                return jsonify({"error": f"Policy '{policy_name}' has no content to activate."}), 500
        else:
            # If deactivating, remove the policy from OPA
            try:
                opa.delete_policy(policy_name)
                logger.info(f"Policy '{policy_name}' deactivated and removed from OPA.")
            except Exception as opa_err:
                logger.error(f"Error removing policy '{policy_name}' from OPA: {opa_err}")
                return jsonify({
                    "error": f"Policy '{policy_name}' marked as inactive but failed to remove from OPA: {str(opa_err)}"
                }), 207  # Partial success
        
        status_verb = "activated" if active else "deactivated"
        return jsonify({
            "message": f"Policy '{policy_name}' successfully {status_verb}.",
            "policy": updated_policy.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Error updating status for policy '{policy_name}': {e}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Policy server with OPA integration')
    parser.add_argument('--use-prebuilt-policies', action='store_true', 
                        help='Use policies from prebuilt_policies.json on startup')
    parser.add_argument('--use-mongodb', action='store_true',
                        help='Use MongoDB as the policy data store (otherwise uses local JSON file)')
    parser.add_argument('--db-file', default='db.json',
                        help='Path to the local db file (default: db.json)')
    parser.add_argument('--prebuilt-policies-file', 
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'prebuilt_policies.json'),
                        help='Path to the prebuilt policies file (default: prebuilt_policies.json in the same directory as server.py)')
    args = parser.parse_args()
    
    # Initialize the policy data store based on command line arguments
    if args.use_mongodb:
        logger.info("Using MongoDB as policy data store")
        policy_data_store = MongoDbPolicyDataStore()
        if not policy_data_store.is_available():
            logger.error("MongoDB is not available. Falling back to local file storage.")
            policy_data_store = LocalPolicyDataStore(args.policies_file)
    else:
        logger.info(f"Using local JSON file ({args.db_file}) as policy data store")
        policy_data_store = LocalPolicyDataStore(args.db_file)
    
    # Attempt to start OPA server in the background
    opa_started = start_opa_server()

    # Load prebuilt policies if requested
    if args.use_prebuilt_policies:
        logger.info(f"Loading prebuilt policies from {args.prebuilt_policies_file}")
        if load_prebuilt_policies(args.prebuilt_policies_file):
            # If OPA started, sync policies
            if opa_started:
                sync_policies_to_opa()
            else:
                logger.warning("Cannot sync to OPA: OPA server failed to start.")
    elif not args.use_prebuilt_policies:
        logger.info("Skipping prebuilt policies because --use-prebuilt-policies flag was not provided.")
        # Still sync existing policies in the data store if OPA is running
        if opa_started and policy_data_store.is_available():
            sync_policies_to_opa()

    # Run the server on all interfaces (0.0.0.0) at port 5000 with debug mode enabled.
    logger.info("Starting Flask server on port 5000...")
    app.run(debug=True, host='0.0.0.0', port=5000)
