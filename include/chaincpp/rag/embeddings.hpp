#pragma once

#include "../security/sandbox.hpp"
#include "../security/secrets.hpp"
#include <vector>
#include <random>
#include <string>
#include <memory>

namespace chaincpp::rag {

// Embedding Model Interface
class EmbeddingModel {
public:
    virtual ~EmbeddingModel() = default;
    
    // Embed a single text
    virtual security::Result<std::vector<float>> embed(const std::string& text) = 0;
    
    // Embed multiple texts (more efficient)
    virtual security::Result<std::vector<std::vector<float>>> embed_batch(
        const std::vector<std::string>& texts
    ) = 0;
    
    // Get embedding dimension
    virtual size_t dimension() const = 0;
    
    // Get model name
    virtual std::string name() const = 0;
};

// OpenAI Embeddings
class OpenAIEmbeddings : public EmbeddingModel {
public:
    struct Config {
        std::string api_key_env_var = "OPENAI_API_KEY";
        std::string model = "text-embedding-ada-002";
        std::string base_url = "https://api.openai.com";
        size_t batch_size = 100;
    };
    
    static security::Result<std::unique_ptr<OpenAIEmbeddings>> create();
    static security::Result<std::unique_ptr<OpenAIEmbeddings>> create(Config cfg);
    ~OpenAIEmbeddings();
    
    security::Result<std::vector<float>> embed(const std::string& text) override;
    security::Result<std::vector<std::vector<float>>> embed_batch(
        const std::vector<std::string>& texts
    ) override;
    
    size_t dimension() const override { return 1536; }  // Ada-002 dimension
    std::string name() const override { return "openai-ada-002"; }
    
private:
    OpenAIEmbeddings() = default;
    
    security::secure_string api_key_;
    Config config_;
};

// Local Embeddings (using llama.cpp or similar)
class LocalEmbeddings : public EmbeddingModel {
public:
    struct Config {
        std::string model_path;
        size_t dimension = 384;  // Default for many local models
        bool use_gpu = false;
    };
    
    static security::Result<std::unique_ptr<LocalEmbeddings>> create(Config cfg);
    ~LocalEmbeddings();
    
    security::Result<std::vector<float>> embed(const std::string& text) override;
    security::Result<std::vector<std::vector<float>>> embed_batch(
        const std::vector<std::string>& texts
    ) override;
    
    size_t dimension() const override { return dimension_; }
    std::string name() const override { return "local-embedding"; }
    
private:
    LocalEmbeddings() = default;
    
    class Impl;
    std::unique_ptr<Impl> impl_;
    size_t dimension_ = 384;
};

} // namespace chaincpp::rag