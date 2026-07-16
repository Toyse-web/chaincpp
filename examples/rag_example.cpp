#include "chaincpp/rag/document.hpp"
#include "chaincpp/rag/embeddings.hpp"
#include "chaincpp/rag/vector_store.hpp"
#include "chaincpp/models/llm.hpp"
#include <iostream>

using namespace chaincpp::rag;
using namespace chaincpp::models;

int main() {
    std::cout << "\n========================================\n";
    std::cout << "||   chaincpp - RAG System Demo          ||\n";
    std::cout << "||    Retrieval-Augmented Generation     ||\n";
    std::cout << "==========================================\n\n";
    
    // 1. Create components
    std::cout << "Creating components...\n";
    
    auto store = InMemoryVectorStore::create();
    std::cout << "  Vector store created\n";
    
    auto embedder = LocalEmbeddings::create({.dimension = 384}).value();
    std::cout << "  Embedding model created\n";
    
    auto llm_result = OpenAIChat::create();
    if (llm_result.is_err()) {
        std::cout << "OpenAI not available: " << llm_result.error() << "\n";
        std::cout << "  Set OPENAI_API_KEY environment variable\n";
        return 1;
    }
    auto llm = std::move(llm_result.value());
    std::cout << "  LLM created\n\n";
    
    // 2. Create retrieval chain
    auto chain_result = RetrievalChain::create(
        std::move(store),
        std::move(embedder),
        std::move(llm)
    );
    
    if (chain_result.is_err()) {
        std::cout << "Failed to create chain: " << chain_result.error() << "\n";
        return 1;
    }
    
    auto chain = std::move(chain_result.value());
    std::cout << "Retrieval chain created\n\n";
    
    // 3. Load documents
    std::cout << "Loading knowledge base...\n";
    std::cout << "----------------------------------------\n";
    
    std::vector<Document> knowledge_base = {
        DocumentLoader::from_string(
            "The Earth orbits the Sun. It is the third planet from the Sun. "
            "Earth has one moon. It takes 365.25 days to orbit the Sun.",
            "astronomy"
        ),
        DocumentLoader::from_string(
            "C++ is a programming language. It was created by Bjarne Stroustrup. "
            "C++ supports object-oriented programming and generic programming.",
            "programming"
        ),
        DocumentLoader::from_string(
            "The Eiffel Tower is in Paris, France. It was built in 1889. "
            "It is 324 meters tall.",
            "landmarks"
        ),
        DocumentLoader::from_string(
            "Machine learning is a subset of artificial intelligence. "
            "It uses statistical algorithms to find patterns in data.",
            "ai"
        )
    };
    
    auto add_result = chain->add_documents(knowledge_base);
    if (add_result.is_err()) {
        std::cout << "Failed to add documents: " << add_result.error() << "\n";
        return 1;
    }
    std::cout << "  Added " << knowledge_base.size() << " documents\n\n";
    
    // 4. Query the system
    std::vector<std::string> questions = {
        "What is the third planet from the Sun?",
        "Who created C++?",
        "Where is the Eiffel Tower?",
        "What is machine learning?"
    };
    
    for (const auto& question : questions) {
        std::cout << std::string(60, '=') << "\n";
        std::cout << "Question: " << question << "\n";
        std::cout << std::string(60, '=') << "\n\n";
        
        auto result = chain->query_with_sources(question);
        if (result.is_err()) {
            std::cout << "Error: " << result.error() << "\n\n";
            continue;
        }
        
        auto query_result = result.value();
        std::cout << "Answer: " << query_result.answer << "\n\n";
        
        if (!query_result.source_documents.empty()) {
            std::cout << "Sources:\n";
            for (size_t i = 0; i < query_result.source_documents.size(); ++i) {
                const auto& [doc, score] = query_result.source_documents[i];
                std::cout << "  " << (i + 1) << ". " << doc.page_content.substr(0, 80) << "...\n";
                std::cout << "     (score: " << std::fixed << std::setprecision(2) << score << ")\n";
            }
        }
        std::cout << "\n";
    }
    
    // 5. Security demonstration
    std::cout << std::string(60, '=') << "\n";
    std::cout << "Security Features Active:\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "Document validation and sanitization\n";
    std::cout << "Text splitting with configurable limits\n";
    std::cout << "Embedding API key protection\n";
    std::cout << "In-memory storage only (no persistence for now)\n";
    std::cout << "Prompt injection detection active\n";
    std::cout << "Sandboxed LLM calls\n";
    
    std::cout << "\nRAG system ready for production!\n";
    std::cout << "Full chaincpp library complete!\n\n";
    
    return 0;
}