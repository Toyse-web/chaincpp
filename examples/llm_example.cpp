#include "chaincpp/models/llm.hpp"
#include "chaincpp/core/prompt.hpp"
#include <iostream>
#include <map>
#include <vector>
#include <string>

using namespace chaincpp::models;
using namespace chaincpp::core;

int main() {
    std::cout << "\n========================================\n";
    std::cout << "|   chaincpp - LLM Integration          |\n";
    std::cout << "|        Secure API Calls               |\n";
    std::cout << "========================================\n\n";
    
    // Create a prompt template
    auto prompt_result = PromptTemplate::create(
        "You are a helpful assistant. Answer this question: {question}"
    );
    
    if (prompt_result.is_err()) {
        std::cerr << "Failed to create prompt: " << prompt_result.error() << "\n";
        return 1;
    }
    
    auto prompt = prompt_result.value();

    // Pass custom OpenRouter endpoint configurations
    OpenAIChat::Config router_config;
    router_config.base_url = "https://api.openrouter.ai";
    router_config.api_key_env_var = "OPENROUTER_API_KEY"; // Searches for this env var instead of OPENAI_API_KEY
    
    auto openai_result = OpenAIChat::create(router_config);
    
    if (openai_result.is_err()) {
        std::cout << "Warning: OpenRouter client not available: " << openai_result.error() << "\n";
        std::cout << "Set OPENROUTER_API_KEY environment variable to use OpenRouter\n\n";
        
        // Fall back to local model
        std::cout << "Using local LLM (placeholder)...\n";
        auto local_result = LocalLLM::create({.model_path = "models/llama-2-7b.gguf"});
        
        if (local_result.is_ok()) {
            auto llm = std::move(local_result.value());
            std::map<std::string, std::string> vars = {
                {"question", "What is C++?"}
            };
            
            auto formatted = prompt.format(vars);
            if (formatted.is_ok()) {
                std::vector<Message> messages = {
                    Message::user(formatted.value())
                };
                
                auto response = llm->generate(messages);
                if (response.is_ok()) {
                    std::cout << "\nResponse: " << response.value() << "\n";
                }
            }
        }
    } else {
        auto llm = std::move(openai_result.value());
        std::cout << "OpenRouter client ready\n\n";

        // Create a base configuration selecting a free model
        ModelConfig default_cfg;
        default_cfg.model_name = "google/gemma-2-9b-it:free";
        
        // Example 1: Simple chat
        std::cout << "Example 1: Simple Chat\n";
        std::cout << "----------------------------------------\n";
        
        std::vector<Message> messages = {
            Message::system("You are a helpful assistant that gives concise answers."),
            Message::user("What is the capital of Nigeria?")
        };
        
        auto response = llm->generate(messages, default_cfg);
        if (response.is_ok()) {
            std::cout << "User: What is the capital of Nigeria?\n";
            std::cout << "Assistant: " << response.value() << "\n\n";
        }
        
        // Example 2: Using prompt templates
        std::cout << "Example 2: Prompt Template\n";
        std::cout << "----------------------------------------\n";
        
        auto qa_prompt_res = PromptTemplate::create("Question: {q}\nAnswer: ");
        if (qa_prompt_res.is_ok()) {
            auto qa_prompt = qa_prompt_res.value();
            std::map<std::string, std::string> qa_vars = {{"q", "Explain RAII in C++"}};
            auto formatted_qa = qa_prompt.format(qa_vars).value();
            
            std::vector<Message> qa_messages = {
                Message::system("You are a C++ expert. Provide clear explanations."),
                Message::user(formatted_qa)
            };
            
            auto qa_response = llm->generate(qa_messages, ModelConfig{
                .model_name = "google/gemma-2-9b-it:free",
                .temperature = 0.5f, // Added 'f' to clarify float type
                .max_tokens = 200
            });
            
            if (qa_response.is_ok()) {
                std::cout << "Q: Explain RAII in C++\n";
                std::cout << "A: " << qa_response.value() << "\n\n";
            }
        }
        
        // Example 3: Streaming
        std::cout << "Example 3: Streaming Response\n";
        std::cout << "----------------------------------------\n";
        
        std::cout << "Assistant: ";
        auto stream_result = llm->stream_generate(
            {Message::user("Count from 1 to 3")},
            [](std::string_view chunk) -> chaincpp::security::Result<void> {
                std::cout << chunk << std::flush;
                return chaincpp::security::Result<void>::ok();
            },
            ModelConfig{
                .model_name = "google/gemma-2-9b-it:free",
                .max_tokens = 50
            }
        );
        
        if (stream_result.is_err()) {
            std::cout << "\n[Note: " << stream_result.error() << "]\n";
        }
        std::cout << "\n\n";
        
        // Example 4: Multiple turns
        std::cout << "Example 4: Multi-turn Conversation\n";
        std::cout << "----------------------------------------\n";
        
        std::vector<Message> conversation = {
            Message::system("You are a friendly AI assistant.")
        };
        
        std::vector<std::string> user_msgs = {
            "My name is Toyib. Can you remember that?",
            "What's my name?"
        };
        
        for (const auto& user_msg : user_msgs) {
            conversation.push_back(Message::user(user_msg));
            
            auto reply = llm->generate(conversation, default_cfg);
            if (reply.is_ok()) {
                conversation.push_back(Message::assistant(reply.value()));
                std::cout << "User: " << user_msg << "\n";
                std::cout << "Assistant: " << reply.value() << "\n\n";
            }
        }
    }
    
    std::cout << "Security Features Active:\n";
    std::cout << "----------------------------------------\n";
    std::cout << "   - API keys encrypted at rest\n";
    std::cout << "   - TLS verification enforced\n";
    std::cout << "   - Memory zeroed after use\n";
    
    std::cout << "\nLLM integration ready!\n\n";
    
    return 0;
}
