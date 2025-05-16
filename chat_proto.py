from datetime import datetime
from uuid import uuid4
from typing import Any

from uagents import Context, Model, Protocol

# Import the necessary components of the chat protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    EndSessionContent,
    StartSessionContent,
    TextContent,
    chat_protocol_spec,
)

from solana_service import analyze_token_risk, TokenAnalysisRequest, TokenAnalysisResponse

# AI Agent Address for structured output processing
AI_AGENT_ADDRESS = 'agent1qvp82vcwuz29vanejlld9lsttc9nu9ha0t7u2vp0z9jsj4f90ucj6ukq89z'

if not AI_AGENT_ADDRESS:
    raise ValueError("AI_AGENT_ADDRESS not set")


def create_text_chat(text: str, end_session: bool = True) -> ChatMessage:
    content = [TextContent(type="text", text=text)]
    if end_session:
        content.append(EndSessionContent(type="end-session"))
    return ChatMessage(
        timestamp=datetime.utcnow(),
        msg_id=uuid4(),
        content=content,
    )


chat_proto = Protocol(spec=chat_protocol_spec)
struct_output_client_proto = Protocol(
    name="StructuredOutputClientProtocol", version="0.1.0"
)


class StructuredOutputPrompt(Model):
    prompt: str
    output_schema: dict[str, Any]


class StructuredOutputResponse(Model):
    output: dict[str, Any]


@chat_proto.on_message(ChatMessage)
async def handle_message(ctx: Context, sender: str, msg: ChatMessage):
    ctx.logger.info(f"Got a message from {sender}: {msg}")
    ctx.storage.set(str(ctx.session), sender)
    await ctx.send(
        sender,
        ChatAcknowledgement(timestamp=datetime.utcnow(),
                            acknowledged_msg_id=msg.msg_id),
    )

    for item in msg.content:
        if isinstance(item, StartSessionContent):
            ctx.logger.info(f"Got a start session message from {sender}")
            continue
        elif isinstance(item, TextContent):
            ctx.logger.info(f"Got a message from {sender}: {item.text}")
            ctx.storage.set(str(ctx.session), sender)
            await ctx.send(
                AI_AGENT_ADDRESS,
                StructuredOutputPrompt(
                    prompt=item.text, output_schema=TokenAnalysisRequest.schema()
                ),
            )
        else:
            ctx.logger.info(f"Got unexpected content from {sender}")


@chat_proto.on_message(ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    ctx.logger.info(
        f"Got an acknowledgement from {sender} for {msg.acknowledged_msg_id}"
    )


@struct_output_client_proto.on_message(StructuredOutputResponse)
async def handle_structured_output_response(
    ctx: Context, sender: str, msg: StructuredOutputResponse
):
    session_sender = ctx.storage.get(str(ctx.session))
    if session_sender is None:
        ctx.logger.error(
            "Discarding message because no session sender found in storage"
        )
        return

    if "<UNKNOWN>" in str(msg.output):
        await ctx.send(
            session_sender,
            create_text_chat(
                "Sorry, I couldn't process your request. Please include a valid Solana token address."
            ),
        )
        return

    try:
        # Parse the structured output to get the token address
        token_request = TokenAnalysisRequest.parse_obj(msg.output)
        token_address = token_request.token_address

        if not token_address:
            await ctx.send(
                session_sender,
                create_text_chat(
                    "Sorry, I couldn't find a valid Solana token address in your query."
                ),
            )
            return

        # Analyze the token for rugpull risk
        analysis = await analyze_token_risk(token_address)

        # Create a detailed response message
        response_parts = [
            f"🔍 Token Risk Analysis for `{token_address}`\n",
            f"Risk Level: {'🚨 ' if analysis.risk_level in ['HIGH', 'CRITICAL'] else ''}{analysis.risk_level}",
            f"Risk Score: {analysis.risk_score:.2f}/1.00\n",
            "\n📊 Risk Factors:",
        ]

        # Add risk factor details
        if "risk_factors" in analysis.analysis_details:
            factors = analysis.analysis_details["risk_factors"]
            response_parts.extend([
                f"• Liquidity Risk: {factors['liquidity_risk']:.2f}",
                f"• Holder Distribution Risk: {factors['holder_distribution_risk']:.2f}",
                f"• Age Risk: {factors['age_risk']:.2f}",
                f"• Volume Risk: {factors['volume_risk']:.2f}",
                f"• Contract Risk: {factors['contract_risk']:.2f}"
            ])

        # Add token details
        if "token_age_days" in analysis.analysis_details:
            response_parts.append(
                f"\n📅 Token Age: {analysis.analysis_details['token_age_days']} days")
        if "token_supply" in analysis.analysis_details:
            response_parts.append(
                f"💰 Token Supply: {analysis.analysis_details['token_supply']:,.0f}")
        if "holder_distribution" in analysis.analysis_details:
            holder_info = analysis.analysis_details["holder_distribution"]
            response_parts.append(
                f"👥 Total Holders: {holder_info['total_holders']}")
            response_parts.append(
                f"📈 Top Holder: {holder_info['top_holder_percentage']*100:.1f}%")

        # Add warnings if any
        if analysis.warnings:
            response_parts.append("\n⚠️ Warnings:")
            for warning in analysis.warnings:
                response_parts.append(f"• {warning}")

        # Add explorer link
        response_parts.append(
            f"\n🔗 [View on Solana Explorer](https://explorer.solana.com/address/{token_address})")

        # Join all parts with newlines
        response_text = "\n".join(response_parts)

        # Send the response back to the user
        await ctx.send(session_sender, create_text_chat(response_text))

    except Exception as err:
        ctx.logger.error(err)
        await ctx.send(
            session_sender,
            create_text_chat(
                "Sorry, I couldn't analyze the token. Please try again later."
            ),
        )
        return
