#pragma once

#include "embeddings.hpp"
#include "document.hpp"
#include "../models/llm.hpp"
#include <vector>
#include <string>
#include <memory>
#include <optional>

namespace chaincpp::rag {

// Vector Store Interface
class VectorStore {
public:
    virtual ~VectorStore() = default;
    
    // Add documents with their embeddings
    virtual security::Result<void> add_documents(
        const std::vector<Document>& documents,
        const std::vector<std::vector<float>>& embeddings
    ) = 0;
    
    // Add a single document (generates embedding)
    virtual security::Result<void> add_document(
        const Document& document,
        EmbeddingModel& embedding_model
    ) = 0;
    
    // Search for similar documents
    virtual security::Result<std::vector<std::pair<Document, float>>> similarity_search(
        const std::vector<float>& query_embedding,
        size_t k = 4
    ) = 0;
    
    // Search by text (generates embedding)
    virtual security::Result<std::vector<std::pair<Document, float>>> similarity_search_by_text(
        const std::string& query,
        EmbeddingModel& embedding_model,
        size_t k = 4
    ) = 0;
    
    // Get all documents
    virtual std::vector<Document> get_all_documents() const = 0;
    
    // Clear all documents
    virtual void clear() = 0;
    
    // Get number of documents
    virtual size_t size() const = 0;
};

// In-Memory Vector Store (Simple)
class InMemoryVectorStore : public VectorStore {
public:
    static std::unique_ptr<InMemoryVectorStore> create();
    
    security::Result<void> add_documents(
        const std::vector<Document>& documents,
        const std::vector<std::vector<float>>& embeddings
    ) override;
    
    security::Result<void> add_document(
        const Document& document,
        EmbeddingModel& embedding_model
    ) override;
    
    security::Result<std::vector<std::pair<Document, float>>> similarity_search(
        const std::vector<float>& query_embedding,
        size_t k = 4
    ) override;
    
    security::Result<std::vector<std::pair<Document, float>>> similarity_search_by_text(
        const std::string& query,
        EmbeddingModel& embedding_model,
        size_t k = 4
    ) override;
    
    std::vector<Document> get_all_documents() const override;
    void clear() override;
    size_t size() const override;
    
private:
    InMemoryVectorStore() = default;
    
    struct StoredDocument {
        Document doc;
        std::vector<float> embedding;
    };
    
    std::vector<StoredDocument> documents_;
    
    static float cosine_similarity(const std::vector<float>& a, const std::vector<float>& b);
};

// Retrieval Chain - Combines vector store with LLM
class RetrievalChain {
public:
    struct Config {
        size_t top_k = 4;
        bool include_source_documents = true;
        // Encapsulate the raw document context block within explicit security guard boundaries
        std::string system_prompt_template = 
            "[SYSTEM_LOCKED]\n"
            "You are a helpful assistant. Use the following context to answer the user's question.\n\n"
            "=== VERIFIED CONTEXT START ===\n{context}\n=== VERIFIED CONTEXT END ===\n\n"
            "Question: {question}\n\n"
            "Answer:";
    };

    static security::Result<std::unique_ptr<RetrievalChain>> create(
        std::unique_ptr<VectorStore> vector_store,
        std::unique_ptr<EmbeddingModel> embedding_model,
        std::unique_ptr<models::BaseLLM> llm
    );
    
    static security::Result<std::unique_ptr<RetrievalChain>> create(
        std::unique_ptr<VectorStore> vector_store,
        std::unique_ptr<EmbeddingModel> embedding_model,
        std::unique_ptr<models::BaseLLM> llm,
        Config config
    );
    
    ~RetrievalChain();
    
    // Query the RAG system
    security::Result<std::string> query(const std::string& question);
    
    // Query with source documents
    struct QueryResult {
        std::string answer;
        std::vector<std::pair<Document, float>> source_documents;
    };
    security::Result<QueryResult> query_with_sources(const std::string& question);
    
    // Add documents to the vector store
    security::Result<void> add_documents(const std::vector<Document>& documents);
    
private:
    RetrievalChain() = default;
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace chaincpp::rag