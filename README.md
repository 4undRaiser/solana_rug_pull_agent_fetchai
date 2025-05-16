# Solana Rug Pull Detector Agent

![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)

- **Agent name:** Solana Rug Pull Detector Agent
- **Agent address:** agent1qg59057886303vjd3sfecgmy0wrtjazhpwqmwhpau3r67uwg5vp755u8qrk

## Description

The Solana Rug Pull Detector Agent is an AI-powered security tool designed to analyze Solana tokens for potential rugpull and scam characteristics. It provides comprehensive risk assessment by analyzing multiple factors including token liquidity, holder distribution, trading patterns, and contract verification status. This agent helps users make informed decisions by identifying potential red flags in token contracts and trading patterns.

## Key Features

- 🔍 **Comprehensive Risk Analysis**: Evaluates multiple risk factors to provide a detailed risk score
- 📊 **Holder Distribution Analysis**: Identifies concentrated token ownership and potential manipulation
- 💧 **Liquidity Analysis**: Assesses token liquidity depth and supply distribution
- ⏱️ **Age Verification**: Evaluates token age and trading history
- 📈 **Trading Pattern Analysis**: Detects suspicious trading activities and volume patterns
- 🔒 **Contract Verification**: Checks contract status and security indicators

## Input Data Model

```python
class TokenAnalysisRequest(Model):
    token_address: str = Field(
        description="Solana token address to analyze for rugpull risk",
    )
```

## Output Data Model

```python
class TokenAnalysisResponse(Model):
    risk_score: float = Field(
        description="Overall risk score (0-1, higher means more risky)",
    )
    risk_level: str = Field(
        description="Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)",
    )
    analysis_details: Dict = Field(
        description="Detailed analysis of the token including all risk factors",
    )
    warnings: List[str] = Field(
        description="List of specific warnings and concerns",
    )
```

## Usage Guidelines

1. **Basic Usage**:

   ```python
   # Example token analysis request
   token_address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
   analysis = await analyze_token_risk(token_address)
   ```

2. **Interpreting Results**:

   - Risk Score (0-1): Higher scores indicate higher risk
   - Risk Levels: LOW (<0.4), MEDIUM (0.4-0.6), HIGH (0.6-0.8), CRITICAL (>0.8)
   - Check warnings for specific concerns
   - Review detailed analysis for comprehensive assessment

3. **Rate Limits**:
   - 30 requests per hour
   - Health check endpoint available for service status

## Risk Factors Analyzed

1. **Liquidity Risk** (30% weight)

   - Token supply analysis
   - Liquidity depth
   - Supply distribution

2. **Holder Distribution** (25% weight)

   - Concentration of ownership
   - Number of holders
   - Top holder percentage

3. **Age Risk** (15% weight)

   - Token creation date
   - Trading history length
   - Market maturity

4. **Volume Risk** (15% weight)

   - Trading activity
   - Volume patterns
   - Transaction history

5. **Contract Risk** (15% weight)
   - Contract verification
   - Code analysis
   - Security indicators

## Technical Details

- **Protocol**: `Solana-Rug-Pull-Detector-Protocol v0.1.0`
- **Dependencies**:
  - uagents
  - solana-py
  - requests
- **API Endpoints**: Solana RPC, Solscan API

## Limitations

- Analysis is based on on-chain data only
- Cannot guarantee 100% accuracy in detecting scams
- May not detect sophisticated rugpull schemes
- Rate limited to prevent API abuse

## Security Considerations

- Always verify results with multiple sources
- Use as part of a broader due diligence process
- Consider consulting with security experts
- Keep API keys and credentials secure

## License

MIT License - See LICENSE file for details

## Contact & Support

- Dev Email: jonathaniheme@gmail.com

## Disclaimer

This tool is provided for informational purposes only. It should not be considered as financial advice. Always conduct your own research and due diligence before making any investment decisions. The developers are not responsible for any financial losses incurred through the use of this tool.
