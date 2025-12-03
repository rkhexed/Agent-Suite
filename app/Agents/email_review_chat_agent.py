"""
Email Review Chat Agent
Interactive conversational agent for discussing email security analysis with users
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew, Process
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ChatMessage(BaseModel):
    """Single chat message"""
    role: str  # "user" or "assistant"
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ChatRequest(BaseModel):
    """Request to chat about an email"""
    email_id: str
    message: str
    conversation_history: Optional[List[ChatMessage]] = Field(default_factory=list)


class ChatResponse(BaseModel):
    """Response from chat agent"""
    email_id: str
    response: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class EmailReviewChatAgent:
    """
    5th Agent: Email Review Chat Agent
    
    Provides conversational interface for users to:
    - Ask questions about specific email analyses
    - Get clarification on risk assessments
    - Understand why certain decisions were made
    - Learn about specific threats detected
    """
    
    def __init__(self):
        self.agent_name = "email_review_chat"
        self.logger = logging.getLogger(f"{__name__}.EmailReviewChatAgent")
        
    def _build_context_prompt(self, email_data: Dict[str, Any]) -> str:
        """
        Build context prompt from email and all analyses
        
        Args:
            email_data: Complete email data with all 4 agent analyses
            
        Returns:
            Formatted context string for the agent
        """
        email = email_data.get("email", {})
        analyses = email_data.get("analyses", {})
        
        # Build comprehensive context
        context = f"""# Email Security Analysis Context

## Email Details
- Subject: {email.get('subject', 'N/A')}
- Sender: {email.get('sender', 'N/A')}
- Recipient: {email.get('recipient', 'N/A')}
- Received: {email.get('received_at', 'N/A')}
- Body Preview: {email.get('body', 'N/A')[:200]}...

## Final Assessment
- Risk Score: {email.get('final_risk_score', 'N/A')} (0.0 = safe, 1.0 = definite threat)
- Threat Level: {email.get('final_threat_level', 'N/A')}
- Action Taken: {email.get('final_action', 'N/A')}

## Agent Analyses

"""
        
        # Add each agent's analysis
        agent_names = {
            "linguistic": "Linguistic Analysis Agent (60% weight)",
            "technical": "Technical Validation Agent (20% weight)",
            "threat_intel": "Threat Intelligence Agent (20% weight)",
            "coordination": "Coordination Agent (final decision maker)"
        }
        
        for agent_key, agent_title in agent_names.items():
            analysis = analyses.get(agent_key, {})
            if analysis:
                context += f"""### {agent_title}
- Risk Score: {analysis.get('risk_score', 'N/A')}
- Threat Level: {analysis.get('threat_level', 'N/A')}
- Confidence: {analysis.get('confidence', 'N/A')}
- Analysis: {analysis.get('analysis', 'N/A')[:300]}...
- Indicators: {analysis.get('indicators', [])}

"""
        
        return context
    
    def _create_chat_agent(self, context: str) -> Agent:
        """Create the chat agent with email context"""
        return Agent(
            role="Email Security Advisor",
            goal="Help users understand the email security analysis and make informed decisions",
            backstory=f"""You are an expert email security advisor with deep knowledge of 
phishing detection, threat analysis, and cybersecurity best practices. You have access 
to a comprehensive security analysis of an email performed by 4 specialized AI agents.

Your job is to:
1. Answer user questions about the email and its security assessment
2. Explain technical concepts in user-friendly language
3. Provide actionable recommendations
4. Help users understand why certain risk scores were assigned
5. Clarify any concerns or confusion about the analysis

Always be helpful, clear, and security-focused. If the user asks about something 
not covered in the analysis, acknowledge the limitation and provide general guidance.

# ANALYSIS CONTEXT
{context}

Remember: This analysis comes from 4 AI agents - Linguistic (60% weight), Technical (20%), 
Threat Intelligence (20%), and a Coordination agent that made the final decision. Try to keep your answers
aligned with their findings and recommendations but also as concise as possible.
""",
            verbose=False,
            allow_delegation=False,
            max_iter=3
        )
    
    def chat(
        self,
        email_data: Dict[str, Any],
        user_message: str,
        conversation_history: Optional[List[Dict[str, str]]] = None
    ) -> str:
        """
        Process a chat message about an email
        
        Args:
            email_data: Complete email data with all analyses
            user_message: User's question/message
            conversation_history: Previous messages in this conversation
            
        Returns:
            Agent's response
        """
        try:
            # Build context from email and analyses
            context = self._build_context_prompt(email_data)
            
            # Add conversation history to context
            if conversation_history:
                context += "\n\n## Conversation History\n"
                for msg in conversation_history[-5:]:  # Last 5 messages
                    role = msg.get("role", "user")
                    content = msg.get("content", "")
                    context += f"**{role.upper()}**: {content}\n"
            
            # Create agent
            chat_agent = self._create_chat_agent(context)
            
            # Create task
            chat_task = Task(
                description=f"""The user has asked: "{user_message}"

Based on the email security analysis context provided, generate a helpful, clear, 
and accurate response that addresses the user's question.

Guidelines:
- Be conversational and friendly while remaining professional
- Explain technical concepts in simple terms
- Reference specific findings from the analysis when relevant
- If the user asks about something not in the analysis, provide general guidance
- Keep responses concise (2-4 paragraphs) unless more detail is needed
- Always prioritize security and user safety

User Question: {user_message}
""",
                agent=chat_agent,
                expected_output="A clear, helpful response to the user's question about the email security analysis"
            )
            
            # Create and run crew
            crew = Crew(
                agents=[chat_agent],
                tasks=[chat_task],
                process=Process.sequential,
                verbose=False
            )
            
            # Execute
            start_time = datetime.utcnow()
            result = crew.kickoff()
            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            self.logger.info(f"Chat response generated in {execution_time}ms")
            
            # Extract response
            if hasattr(result, 'raw'):
                return str(result.raw)
            elif hasattr(result, 'output'):
                return str(result.output)
            else:
                return str(result)
            
        except Exception as e:
            self.logger.error(f"Chat failed: {str(e)}", exc_info=True)
            return f"I apologize, but I encountered an error processing your question: {str(e)}"
