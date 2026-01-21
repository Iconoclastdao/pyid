from fastapi import FastAPI, APIRouter, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import hashlib
import secrets
import json
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Secret
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_ALGORITHM = "HS256"

app = FastAPI(title="Identity Kernel Foundation")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class DIDCreate(BaseModel):
    mnemonic: Optional[str] = None  # If None, generate new

class DIDResponse(BaseModel):
    did: str
    public_key: str
    created_at: str
    karma: float = 0.0
    mnemonic: Optional[str] = None  # Only returned on creation

class PolicyKeyCreate(BaseModel):
    subject: str
    verb: str
    object_ref: str
    constraints: Optional[Dict[str, Any]] = None
    expires_at: Optional[str] = None

class PolicyKeyResponse(BaseModel):
    id: str
    did: str
    subject: str
    verb: str
    object_ref: str
    constraints: Optional[Dict[str, Any]]
    created_at: str
    expires_at: Optional[str]
    revoked: bool = False

class PulseCreate(BaseModel):
    action_type: str
    impact_score: float = 1.0
    context: Optional[Dict[str, Any]] = None
    dependencies: Optional[List[str]] = None

class PulseResponse(BaseModel):
    id: str
    origin_did: str
    agent_id: Optional[str]
    timestamp: str
    action_type: str
    impact_score: float
    context: Optional[Dict[str, Any]]
    dependencies: List[str]
    hash: str
    prev_hash: Optional[str]

class AgentCreate(BaseModel):
    name: str
    agent_type: str = "worker"
    config: Optional[Dict[str, Any]] = None

class AgentResponse(BaseModel):
    id: str
    did: str
    name: str
    agent_type: str
    status: str
    created_at: str
    config: Optional[Dict[str, Any]]
    karma: float = 0.0

class ProposalCreate(BaseModel):
    title: str
    description: str
    proposal_type: str = "general"
    voting_deadline_hours: int = 168  # 7 days default

class ProposalResponse(BaseModel):
    id: str
    did: str
    title: str
    description: str
    proposal_type: str
    status: str
    votes_for: float = 0.0
    votes_against: float = 0.0
    created_at: str
    voting_deadline: str

class VoteCreate(BaseModel):
    proposal_id: str
    vote: str  # "for" or "against"

class StakeCreate(BaseModel):
    amount: float
    duration_days: int = 30

class StakeResponse(BaseModel):
    id: str
    did: str
    amount: float
    duration_days: int
    staked_at: str
    unlocks_at: str
    status: str

class ChatMessage(BaseModel):
    channel_id: str
    content: str

class ChatMessageResponse(BaseModel):
    id: str
    channel_id: str
    did: str
    content: str
    timestamp: str

class ChannelCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_private: bool = False

class FeedPostCreate(BaseModel):
    content: str
    tags: Optional[List[str]] = None

class AIQueryRequest(BaseModel):
    prompt: str
    context: Optional[Dict[str, Any]] = None

# ==================== HELPERS ====================

def generate_mnemonic():
    """Generate a 24-word mnemonic for key derivation"""
    words = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
             "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
             "acoustic", "acquire", "across", "act", "action", "actor", "actual", "adapt",
             "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice",
             "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree",
             "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol"]
    return " ".join(secrets.choice(words) for _ in range(24))

def derive_keys_from_mnemonic(mnemonic: str):
    """Deterministically derive DID and keys from mnemonic"""
    seed = hashlib.sha256(mnemonic.encode()).hexdigest()
    did = f"did:kernel:{seed[:32]}"
    public_key = hashlib.sha256((seed + "public").encode()).hexdigest()
    private_key = hashlib.sha256((seed + "private").encode()).hexdigest()
    return did, public_key, private_key

def compute_pulse_hash(pulse_data: dict, prev_hash: Optional[str] = None):
    """Compute deterministic hash for pulse"""
    data = json.dumps({
        "origin_did": pulse_data["origin_did"],
        "timestamp": pulse_data["timestamp"],
        "action_type": pulse_data["action_type"],
        "prev_hash": prev_hash
    }, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()

def create_jwt(did: str):
    """Create JWT token for DID authentication"""
    payload = {
        "did": did,
        "exp": datetime.now(timezone.utc).timestamp() + 86400 * 7  # 7 days
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_did(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate JWT and return current DID"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        did = payload.get("did")
        if not did:
            raise HTTPException(status_code=401, detail="Invalid token")
        # Verify DID exists
        identity = await db.identities.find_one({"did": did}, {"_id": 0})
        if not identity:
            raise HTTPException(status_code=401, detail="DID not found")
        return did
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ==================== IDENTITY ENDPOINTS ====================

@api_router.post("/identity/create", response_model=DIDResponse)
async def create_identity(data: DIDCreate):
    """Create new DID or recover from mnemonic"""
    mnemonic = data.mnemonic or generate_mnemonic()
    did, public_key, private_key = derive_keys_from_mnemonic(mnemonic)
    
    # Check if DID exists
    existing = await db.identities.find_one({"did": did}, {"_id": 0})
    if existing:
        token = create_jwt(did)
        return DIDResponse(
            did=did,
            public_key=existing["public_key"],
            created_at=existing["created_at"],
            karma=existing.get("karma", 0.0),
            mnemonic=None  # Don't return mnemonic for recovery
        )
    
    timestamp = datetime.now(timezone.utc).isoformat()
    identity_doc = {
        "did": did,
        "public_key": public_key,
        "created_at": timestamp,
        "karma": 0.0,
        "status": "active"
    }
    await db.identities.insert_one(identity_doc)
    
    # Create genesis pulse
    genesis_pulse = {
        "id": str(uuid.uuid4()),
        "origin_did": did,
        "agent_id": None,
        "timestamp": timestamp,
        "action_type": "identity_created",
        "impact_score": 10.0,
        "context": {"event": "genesis"},
        "dependencies": [],
        "prev_hash": None
    }
    genesis_pulse["hash"] = compute_pulse_hash(genesis_pulse, None)
    await db.pulses.insert_one(genesis_pulse)
    
    return DIDResponse(
        did=did,
        public_key=public_key,
        created_at=timestamp,
        karma=0.0,
        mnemonic=mnemonic  # Return mnemonic only on creation
    )

@api_router.post("/identity/auth")
async def authenticate(data: DIDCreate):
    """Authenticate with mnemonic and get JWT"""
    if not data.mnemonic:
        raise HTTPException(status_code=400, detail="Mnemonic required")
    
    did, _, _ = derive_keys_from_mnemonic(data.mnemonic)
    identity = await db.identities.find_one({"did": did}, {"_id": 0})
    
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    
    token = create_jwt(did)
    return {"token": token, "did": did, "karma": identity.get("karma", 0.0)}

@api_router.get("/identity/me", response_model=DIDResponse)
async def get_my_identity(did: str = Depends(get_current_did)):
    """Get current authenticated identity"""
    identity = await db.identities.find_one({"did": did}, {"_id": 0})
    return DIDResponse(**identity)

@api_router.get("/identity/{target_did}")
async def get_identity(target_did: str):
    """Get public identity info"""
    identity = await db.identities.find_one({"did": target_did}, {"_id": 0, "public_key": 1, "created_at": 1, "karma": 1, "did": 1})
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity

# ==================== POLICY KEY ENDPOINTS ====================

@api_router.post("/keys", response_model=PolicyKeyResponse)
async def create_policy_key(data: PolicyKeyCreate, did: str = Depends(get_current_did)):
    """Create a new policy key (capability)"""
    timestamp = datetime.now(timezone.utc).isoformat()
    key_doc = {
        "id": str(uuid.uuid4()),
        "did": did,
        "subject": data.subject,
        "verb": data.verb,
        "object_ref": data.object_ref,
        "constraints": data.constraints,
        "created_at": timestamp,
        "expires_at": data.expires_at,
        "revoked": False
    }
    await db.policy_keys.insert_one(key_doc)
    
    # Emit pulse
    await emit_pulse(did, "policy_key_created", 2.0, {"key_id": key_doc["id"], "verb": data.verb})
    
    return PolicyKeyResponse(**key_doc)

@api_router.get("/keys", response_model=List[PolicyKeyResponse])
async def list_policy_keys(did: str = Depends(get_current_did)):
    """List all policy keys for current DID"""
    keys = await db.policy_keys.find({"did": did, "revoked": False}, {"_id": 0}).to_list(1000)
    return keys

@api_router.delete("/keys/{key_id}")
async def revoke_policy_key(key_id: str, did: str = Depends(get_current_did)):
    """Revoke a policy key"""
    result = await db.policy_keys.update_one(
        {"id": key_id, "did": did},
        {"$set": {"revoked": True}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Key not found or already revoked")
    
    await emit_pulse(did, "policy_key_revoked", -1.0, {"key_id": key_id})
    return {"status": "revoked"}

# ==================== PULSE ENDPOINTS ====================

async def emit_pulse(did: str, action_type: str, impact_score: float, context: dict = None, agent_id: str = None, dependencies: list = None):
    """Internal helper to emit pulses and update karma"""
    # Get previous pulse hash
    last_pulse = await db.pulses.find_one(
        {"origin_did": did},
        {"_id": 0, "hash": 1},
        sort=[("timestamp", -1)]
    )
    prev_hash = last_pulse["hash"] if last_pulse else None
    
    timestamp = datetime.now(timezone.utc).isoformat()
    pulse_doc = {
        "id": str(uuid.uuid4()),
        "origin_did": did,
        "agent_id": agent_id,
        "timestamp": timestamp,
        "action_type": action_type,
        "impact_score": impact_score,
        "context": context or {},
        "dependencies": dependencies or [],
        "prev_hash": prev_hash
    }
    pulse_doc["hash"] = compute_pulse_hash(pulse_doc, prev_hash)
    await db.pulses.insert_one(pulse_doc)
    
    # Update karma (capped per-DID impact)
    max_impact = 10.0
    capped_impact = min(impact_score, max_impact)
    await db.identities.update_one(
        {"did": did},
        {"$inc": {"karma": capped_impact}}
    )
    
    return pulse_doc

@api_router.post("/pulses", response_model=PulseResponse)
async def create_pulse(data: PulseCreate, did: str = Depends(get_current_did)):
    """Create a new pulse (atomic execution signal)"""
    pulse = await emit_pulse(
        did, 
        data.action_type, 
        data.impact_score, 
        data.context, 
        dependencies=data.dependencies
    )
    return PulseResponse(**pulse)

@api_router.get("/pulses", response_model=List[PulseResponse])
async def list_pulses(
    did: str = Depends(get_current_did),
    limit: int = Query(50, le=200),
    action_type: Optional[str] = None
):
    """List pulses for current DID"""
    query = {"origin_did": did}
    if action_type:
        query["action_type"] = action_type
    pulses = await db.pulses.find(query, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return pulses

@api_router.get("/pulses/all", response_model=List[PulseResponse])
async def list_all_pulses(limit: int = Query(50, le=200)):
    """List all recent pulses (public feed)"""
    pulses = await db.pulses.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return pulses

@api_router.get("/pulses/{pulse_id}", response_model=PulseResponse)
async def get_pulse(pulse_id: str):
    """Get a specific pulse by ID"""
    pulse = await db.pulses.find_one({"id": pulse_id}, {"_id": 0})
    if not pulse:
        raise HTTPException(status_code=404, detail="Pulse not found")
    return pulse

# ==================== AGENT ENDPOINTS ====================

@api_router.post("/agents", response_model=AgentResponse)
async def spawn_agent(data: AgentCreate, did: str = Depends(get_current_did)):
    """Spawn a new agent"""
    timestamp = datetime.now(timezone.utc).isoformat()
    agent_doc = {
        "id": str(uuid.uuid4()),
        "did": did,
        "name": data.name,
        "agent_type": data.agent_type,
        "status": "active",
        "created_at": timestamp,
        "config": data.config or {},
        "karma": 0.0,
        "checkpoints": []
    }
    await db.agents.insert_one(agent_doc)
    
    await emit_pulse(did, "agent_spawned", 5.0, {"agent_id": agent_doc["id"], "name": data.name})
    
    return AgentResponse(**agent_doc)

@api_router.get("/agents", response_model=List[AgentResponse])
async def list_agents(did: str = Depends(get_current_did)):
    """List all agents for current DID"""
    agents = await db.agents.find({"did": did}, {"_id": 0, "checkpoints": 0}).to_list(100)
    return agents

@api_router.post("/agents/{agent_id}/checkpoint")
async def checkpoint_agent(agent_id: str, did: str = Depends(get_current_did)):
    """Create a checkpoint for agent state"""
    agent = await db.agents.find_one({"id": agent_id, "did": did}, {"_id": 0})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    checkpoint = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "state_hash": hashlib.sha256(json.dumps(agent, sort_keys=True).encode()).hexdigest()
    }
    
    await db.agents.update_one(
        {"id": agent_id},
        {"$push": {"checkpoints": checkpoint}}
    )
    
    await emit_pulse(did, "agent_checkpoint", 1.0, {"agent_id": agent_id, "checkpoint_id": checkpoint["id"]}, agent_id=agent_id)
    
    return checkpoint

@api_router.post("/agents/{agent_id}/terminate")
async def terminate_agent(agent_id: str, did: str = Depends(get_current_did)):
    """Terminate an agent"""
    result = await db.agents.update_one(
        {"id": agent_id, "did": did},
        {"$set": {"status": "terminated"}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    await emit_pulse(did, "agent_terminated", -2.0, {"agent_id": agent_id}, agent_id=agent_id)
    
    return {"status": "terminated"}

# ==================== GOVERNANCE ENDPOINTS ====================

@api_router.post("/governance/proposals", response_model=ProposalResponse)
async def create_proposal(data: ProposalCreate, did: str = Depends(get_current_did)):
    """Create a new governance proposal"""
    timestamp = datetime.now(timezone.utc)
    deadline = timestamp.timestamp() + (data.voting_deadline_hours * 3600)
    
    proposal_doc = {
        "id": str(uuid.uuid4()),
        "did": did,
        "title": data.title,
        "description": data.description,
        "proposal_type": data.proposal_type,
        "status": "active",
        "votes_for": 0.0,
        "votes_against": 0.0,
        "voters": [],
        "created_at": timestamp.isoformat(),
        "voting_deadline": datetime.fromtimestamp(deadline, timezone.utc).isoformat()
    }
    await db.proposals.insert_one(proposal_doc)
    
    await emit_pulse(did, "proposal_created", 3.0, {"proposal_id": proposal_doc["id"], "title": data.title})
    
    return ProposalResponse(**{k: v for k, v in proposal_doc.items() if k != "voters"})

@api_router.get("/governance/proposals", response_model=List[ProposalResponse])
async def list_proposals(status: Optional[str] = None):
    """List all proposals"""
    query = {}
    if status:
        query["status"] = status
    proposals = await db.proposals.find(query, {"_id": 0, "voters": 0}).sort("created_at", -1).to_list(100)
    return proposals

@api_router.post("/governance/vote")
async def cast_vote(data: VoteCreate, did: str = Depends(get_current_did)):
    """Cast a vote on a proposal (karma-weighted)"""
    proposal = await db.proposals.find_one({"id": data.proposal_id}, {"_id": 0})
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    
    if proposal["status"] != "active":
        raise HTTPException(status_code=400, detail="Voting closed")
    
    if did in proposal.get("voters", []):
        raise HTTPException(status_code=400, detail="Already voted")
    
    # Get voter's karma for weighted voting
    identity = await db.identities.find_one({"did": did}, {"_id": 0, "karma": 1})
    vote_weight = max(1.0, identity.get("karma", 0.0) / 10)  # Min weight of 1
    
    field = "votes_for" if data.vote == "for" else "votes_against"
    await db.proposals.update_one(
        {"id": data.proposal_id},
        {"$inc": {field: vote_weight}, "$push": {"voters": did}}
    )
    
    await emit_pulse(did, "vote_cast", 1.0, {"proposal_id": data.proposal_id, "vote": data.vote, "weight": vote_weight})
    
    return {"status": "voted", "weight": vote_weight}

# ==================== ECONOMY ENDPOINTS ====================

@api_router.post("/economy/stake", response_model=StakeResponse)
async def create_stake(data: StakeCreate, did: str = Depends(get_current_did)):
    """Create a new stake"""
    timestamp = datetime.now(timezone.utc)
    unlocks_at = timestamp.timestamp() + (data.duration_days * 86400)
    
    stake_doc = {
        "id": str(uuid.uuid4()),
        "did": did,
        "amount": data.amount,
        "duration_days": data.duration_days,
        "staked_at": timestamp.isoformat(),
        "unlocks_at": datetime.fromtimestamp(unlocks_at, timezone.utc).isoformat(),
        "status": "active"
    }
    await db.stakes.insert_one(stake_doc)
    
    await emit_pulse(did, "stake_created", data.amount * 0.1, {"stake_id": stake_doc["id"], "amount": data.amount})
    
    return StakeResponse(**stake_doc)

@api_router.get("/economy/stakes", response_model=List[StakeResponse])
async def list_stakes(did: str = Depends(get_current_did)):
    """List all stakes for current DID"""
    stakes = await db.stakes.find({"did": did}, {"_id": 0}).to_list(100)
    return stakes

@api_router.get("/economy/stats")
async def get_economy_stats():
    """Get overall economy statistics"""
    total_karma = await db.identities.aggregate([
        {"$group": {"_id": None, "total": {"$sum": "$karma"}}}
    ]).to_list(1)
    
    total_staked = await db.stakes.aggregate([
        {"$match": {"status": "active"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    
    total_pulses = await db.pulses.count_documents({})
    total_identities = await db.identities.count_documents({})
    
    return {
        "total_karma": total_karma[0]["total"] if total_karma else 0,
        "total_staked": total_staked[0]["total"] if total_staked else 0,
        "total_pulses": total_pulses,
        "total_identities": total_identities
    }

@api_router.get("/economy/leaderboard")
async def get_leaderboard(limit: int = Query(10, le=50)):
    """Get karma leaderboard"""
    leaders = await db.identities.find(
        {}, {"_id": 0, "did": 1, "karma": 1, "created_at": 1}
    ).sort("karma", -1).to_list(limit)
    return leaders

# ==================== SOCIAL ENDPOINTS ====================

@api_router.post("/social/channels")
async def create_channel(data: ChannelCreate, did: str = Depends(get_current_did)):
    """Create a new chat channel"""
    channel_doc = {
        "id": str(uuid.uuid4()),
        "name": data.name,
        "description": data.description,
        "is_private": data.is_private,
        "created_by": did,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "members": [did]
    }
    await db.channels.insert_one(channel_doc)
    
    await emit_pulse(did, "channel_created", 2.0, {"channel_id": channel_doc["id"], "name": data.name})
    
    return {k: v for k, v in channel_doc.items() if k != "_id"}

@api_router.get("/social/channels")
async def list_channels(did: str = Depends(get_current_did)):
    """List available channels"""
    channels = await db.channels.find(
        {"$or": [{"is_private": False}, {"members": did}]},
        {"_id": 0}
    ).to_list(100)
    return channels

@api_router.post("/social/messages", response_model=ChatMessageResponse)
async def send_message(data: ChatMessage, did: str = Depends(get_current_did)):
    """Send a chat message"""
    msg_doc = {
        "id": str(uuid.uuid4()),
        "channel_id": data.channel_id,
        "did": did,
        "content": data.content,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.messages.insert_one(msg_doc)
    
    await emit_pulse(did, "message_sent", 0.5, {"channel_id": data.channel_id})
    
    return ChatMessageResponse(**msg_doc)

@api_router.get("/social/messages/{channel_id}", response_model=List[ChatMessageResponse])
async def get_channel_messages(channel_id: str, limit: int = Query(50, le=200)):
    """Get messages from a channel"""
    messages = await db.messages.find(
        {"channel_id": channel_id}, {"_id": 0}
    ).sort("timestamp", -1).to_list(limit)
    return messages[::-1]  # Reverse to chronological order

@api_router.post("/social/feed")
async def create_feed_post(data: FeedPostCreate, did: str = Depends(get_current_did)):
    """Create a feed post"""
    post_doc = {
        "id": str(uuid.uuid4()),
        "did": did,
        "content": data.content,
        "tags": data.tags or [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reactions": {}
    }
    await db.feed_posts.insert_one(post_doc)
    
    await emit_pulse(did, "feed_post_created", 1.0, {"post_id": post_doc["id"]})
    
    return {k: v for k, v in post_doc.items() if k != "_id"}

@api_router.get("/social/feed")
async def get_feed(limit: int = Query(50, le=200)):
    """Get social feed"""
    posts = await db.feed_posts.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return posts

# ==================== AI ENDPOINTS (Mock Local Ollama) ====================

@api_router.post("/ai/query")
async def ai_query(data: AIQueryRequest, did: str = Depends(get_current_did)):
    """Query local AI (deterministic mock)"""
    # Deterministic response based on prompt hash
    prompt_hash = hashlib.sha256(data.prompt.encode()).hexdigest()[:16]
    
    # Simulated AI responses based on prompt patterns
    responses = {
        "help": "I am the Identity Kernel AI assistant. I can help you with DID management, pulse analysis, governance participation, and more.",
        "karma": "Karma is a deterministic reputation score based on your pulses. It affects voting weight and visibility but doesn't grant authority.",
        "pulse": "Pulses are atomic, signed execution records. They form a hash-linked chain for verifiable history.",
        "agent": "Agents are isolated execution contexts scoped under your DID. They can run tasks, store state, and communicate via kernel-mediated IPC.",
        "default": f"Processing query with deterministic seed {prompt_hash}. In a full implementation, this would connect to a local Ollama instance for frozen/unfrozen model inference."
    }
    
    response_key = "default"
    for key in responses:
        if key in data.prompt.lower():
            response_key = key
            break
    
    await emit_pulse(did, "ai_query", 0.5, {"prompt_hash": prompt_hash})
    
    return {
        "response": responses[response_key],
        "deterministic_seed": prompt_hash,
        "model": "ollama-kernel-frozen",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# ==================== RECOVERY ENDPOINTS ====================

@api_router.post("/recovery/export")
async def export_state(did: str = Depends(get_current_did)):
    """Export full state for backup/recovery"""
    identity = await db.identities.find_one({"did": did}, {"_id": 0})
    pulses = await db.pulses.find({"origin_did": did}, {"_id": 0}).to_list(10000)
    agents = await db.agents.find({"did": did}, {"_id": 0}).to_list(100)
    keys = await db.policy_keys.find({"did": did}, {"_id": 0}).to_list(100)
    stakes = await db.stakes.find({"did": did}, {"_id": 0}).to_list(100)
    
    export_data = {
        "version": "1.2",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "identity": identity,
        "pulses": pulses,
        "agents": agents,
        "policy_keys": keys,
        "stakes": stakes
    }
    
    return export_data

@api_router.get("/recovery/verify")
async def verify_pulse_chain(did: str = Depends(get_current_did)):
    """Verify integrity of pulse chain"""
    pulses = await db.pulses.find(
        {"origin_did": did}, {"_id": 0}
    ).sort("timestamp", 1).to_list(10000)
    
    if not pulses:
        return {"valid": True, "pulse_count": 0}
    
    valid = True
    broken_at = None
    
    for i, pulse in enumerate(pulses):
        expected_prev = pulses[i-1]["hash"] if i > 0 else None
        if pulse.get("prev_hash") != expected_prev:
            valid = False
            broken_at = pulse["id"]
            break
    
    return {
        "valid": valid,
        "pulse_count": len(pulses),
        "broken_at": broken_at
    }

# ==================== HEALTH & STATUS ====================

@api_router.get("/")
async def root():
    return {"message": "Identity Kernel Foundation API v1.2", "status": "operational"}

@api_router.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# Include router and middleware
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
