import os
from enum import Enum

from uagents import Agent, Context, Model
from uagents.experimental.quota import QuotaProtocol, RateLimit
from uagents_core.models import ErrorMessage

from chat_proto import chat_proto, struct_output_client_proto
from solana_service import (
    analyze_token_risk,
    TokenAnalysisRequest,
    TokenAnalysisResponse
)

# Test token address for health checks (USDC token address on Solana)
TEST_TOKEN_ADDRESS = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

agent = Agent()

proto = QuotaProtocol(
    storage_reference=agent.storage,
    name="Solana-Rug-Pull-Detector-Protocol",
    version="0.1.0",
    default_rate_limit=RateLimit(window_size_minutes=60, max_requests=30),
)


@proto.on_message(
    TokenAnalysisRequest, replies={TokenAnalysisResponse, ErrorMessage}
)
async def handle_request(ctx: Context, sender: str, msg: TokenAnalysisRequest):
    ctx.logger.info(
        f"Received token risk analysis request for address: {msg.token_address}")
    try:
        analysis = await analyze_token_risk(msg.token_address)
        ctx.logger.info(
            f"Successfully analyzed token risk for {msg.token_address}")
        await ctx.send(sender, analysis)
    except Exception as err:
        ctx.logger.error(err)
        await ctx.send(sender, ErrorMessage(error=str(err)))

agent.include(proto, publish_manifest=True)

# Health check related code


def agent_is_healthy() -> bool:
    """
    Implement the actual health check logic here.
    Checks if the agent can connect to the Solana RPC API and analyze a known token.
    """
    try:
        import asyncio
        # Test with USDC token address
        result = asyncio.run(analyze_token_risk(TEST_TOKEN_ADDRESS))
        # Basic validation of the response
        return (
            isinstance(result, TokenAnalysisResponse) and
            hasattr(result, 'risk_score') and
            hasattr(result, 'risk_level') and
            hasattr(result, 'analysis_details')
        )
    except Exception as e:
        print(f"Health check failed: {str(e)}")
        return False


class HealthCheck(Model):
    pass


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class AgentHealth(Model):
    agent_name: str
    status: HealthStatus
    details: dict = {}  # Added to provide more health check details


health_protocol = QuotaProtocol(
    storage_reference=agent.storage, name="HealthProtocol", version="0.1.0"
)


@health_protocol.on_message(HealthCheck, replies={AgentHealth})
async def handle_health_check(ctx: Context, sender: str, msg: HealthCheck):
    status = HealthStatus.UNHEALTHY
    details = {"error": None}

    try:
        if agent_is_healthy():
            status = HealthStatus.HEALTHY
            details = {
                "last_check": "successful",
                "test_token": TEST_TOKEN_ADDRESS,
                "capabilities": [
                    "token_risk_analysis",
                    "holder_distribution_analysis",
                    "liquidity_analysis",
                    "trading_volume_analysis"
                ]
            }
    except Exception as err:
        ctx.logger.error(err)
        details["error"] = str(err)
    finally:
        await ctx.send(
            sender,
            AgentHealth(
                agent_name="Rug Pull Detector Agent",
                status=status,
                details=details
            )
        )

agent.include(health_protocol, publish_manifest=True)
agent.include(chat_proto, publish_manifest=True)
agent.include(struct_output_client_proto, publish_manifest=True)

if __name__ == "__main__":
    agent.run()
