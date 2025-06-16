import json
import os
from datetime import datetime
import threading

def get_conversation_filename(user1, user2):
    """
    Generates a consistent filename for a conversation between two users.
    Uses sorted usernames to ensure the filename is always the same regardless of order.
    """
    users = sorted([user1, user2])
    return f"chat_history_{users[0]}_{users[1]}.json"

def get_message_request_filename(receiver_username):
    """
    Generates a filename for message requests for a specific receiver.
    """
    return f"message_requests_{receiver_username}.json"

def get_current_timestamp():
    """
    Returns the current timestamp in a readable string format.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_history(filename):
    """
    Loads chat history from a JSON file.
    Returns an empty list if the file doesn't exist or is corrupted.
    """
    if not os.path.exists(filename):
        return []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            # Handle empty file case
            content = f.read()
            if not content:
                return []
            return json.loads(content)
    except json.JSONDecodeError:
        print(f"[History] Error decoding JSON from {filename}. File might be corrupted or empty.")
        return []
    except Exception as e:
        print(f"[History] Error loading history from {filename}: {e}")
        return []

def get_chat_history(current_user, other_user, lock: threading.Lock):
    """
    Loads the conversation history between two users and formats it for the UI.
    It determines whether each message was 'sent' or 'received' from the
    perspective of the 'current_user'.
    """
    filename = get_conversation_filename(current_user, other_user)
    
    with lock:
        full_history = load_history(filename)

    formatted_history = []
    for msg in full_history:
        # Determine the type ('sent' or 'received') based on the message sender
        msg_type = 'sent' if msg['sender'] == current_user else 'received'
        
        # Adapt the saved message format to what the UI expects
        formatted_history.append({
            'sender': msg['sender'],
            'message': msg.get('content', ''),
            'type': msg_type
        })
        
    return formatted_history

def save_message(sender, receiver, content, status, lock: threading.Lock):
    """
    Saves a single message to the relevant chat history file.
    'status' was originally used to know if a message was sent/received at the time of saving.
    We will retain it for potential future use, but the new get_chat_history provides the final perspective.
    """
    filename = get_conversation_filename(sender, receiver)
    new_message = {
        'timestamp': get_current_timestamp(),
        'sender': sender,
        'receiver': receiver,
        'content': content,
        'status': status # 'sent' or 'received' from the perspective of the original saver
    }

    with lock:
        history = load_history(filename)
        history.append(new_message)
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=4)
        except Exception as e:
            print(f"[History] Error saving message to {filename}: {e}")

def load_message_requests(receiver_username):
    """
    Loads pending message requests for a given receiver from their request file.
    """
    filename = get_message_request_filename(receiver_username)
    if not os.path.exists(filename):
        return {}
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content:
                return {}
            return json.loads(content)
    except json.JSONDecodeError:
        print(f"[Requests] Error decoding JSON from {filename}. Message request file might be corrupted.")
        return {}
    except Exception as e:
        print(f"[Requests] Error loading message requests from {filename}: {e}")
        return {}

def save_message_request(sender, receiver, message_content):
    """
    Saves a message that came from an unfollowed sender as a request.
    """
    filename = get_message_request_filename(receiver)
    requests = load_message_requests(receiver)
    if sender not in requests:
        requests[sender] = []
    requests[sender].append({
        'timestamp': get_current_timestamp(),
        'sender': sender,
        'message': message_content
    })
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(requests, f, indent=4)
        print(f"[Requests] New message request saved from '{sender}' to '{receiver}'.")
    except Exception as e:
        print(f"[Requests] Error saving message request to {filename}: {e}")

def promote_requests_to_history(sender_of_request, receiver_username, lock: threading.Lock):
    """
    Moves all pending messages from a specific sender (who is now followed)
    from the request file into the main chat history.
    """
    request_filename = get_message_request_filename(receiver_username)
    requests = load_message_requests(receiver_username)

    if sender_of_request in requests:
        messages_to_promote = requests.pop(sender_of_request)
        for msg_data in messages_to_promote:
            save_message(msg_data['sender'], receiver_username, msg_data['message'], 'received', lock)
        
        try:
            with open(request_filename, 'w', encoding='utf-8') as f:
                json.dump(requests, f, indent=4)
            print(f"[Requests] Promoted {len(messages_to_promote)} messages from '{sender_of_request}' to chat history and removed requests.")
        except Exception as e:
            print(f"[Requests] Error updating message request file after promotion: {e}")

def remove_message_request(sender_of_request, receiver_username):
    """
    Removes all pending messages from a specific sender from the request file.
    Used when a request is ignored or no longer needed.
    """
    request_filename = get_message_request_filename(receiver_username)
    requests = load_message_requests(receiver_username)

    if sender_of_request in requests:
        requests.pop(sender_of_request)
        try:
            with open(request_filename, 'w', encoding='utf-8') as f:
                json.dump(requests, f, indent=4)
            print(f"[Requests] Removed message requests from '{sender_of_request}'.")
        except Exception as e:
            print(f"[Requests] Error removing message request from {filename}: {e}")