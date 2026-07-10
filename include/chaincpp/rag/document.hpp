#pragma once

#include "../security/sandbox.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace chaincpp::rag {

// Document - Raw text with metadata

struct Document {
    std::string page_content;
    std::map<std::string, std::string> metadata;
    std::string id;
    
    Document() = default;
    Document(std::string content, std::map<std::string, std::string> meta = {})
        : page_content(std::move(content)), metadata(std::move(meta)) {}
    
    // Generate a unique ID if not provided
    void ensure_id();
    
    // Convert to JSON
    std::string to_json() const;
    
    // Create from JSON
    static security::Result<Document> from_json(const std::string& json_str);
};

// Document Chunk - A piece of a larger document

struct DocumentChunk {
    std::string content;
    std::map<std::string, std::string> metadata;
    std::string parent_id;
    size_t chunk_index = 0;
    size_t total_chunks = 0;
    
    // Convert to Document
    Document to_document() const;
};

// Text Splitter - Split documents into chunks

class TextSplitter {
public:
    struct Config {
        size_t chunk_size = 1000;        // Characters per chunk
        size_t chunk_overlap = 200;      // Overlap between chunks
        std::vector<std::string> separators = {"\n\n", "\n", ". ", " ", ""};
        bool keep_separator = true;
    };
    
    explicit TextSplitter(Config config = {});
    
    // Split a single document
    std::vector<DocumentChunk> split_document(const Document& doc) const;
    
    // Split multiple documents
    std::vector<DocumentChunk> split_documents(const std::vector<Document>& docs) const;
    
    // Split text directly
    std::vector<std::string> split_text(const std::string& text) const;
    
private:
    Config config_;
    
    std::vector<std::string> split_with_separators(const std::string& text) const;
    std::vector<std::string> merge_splits(const std::vector<std::string>& splits) const;
};

// Document Loader - Load documents from various sources

class DocumentLoader {
public:
    // Load from a text file
    static security::Result<Document> load_text_file(
        const std::string& filepath,
        const std::vector<std::string>& allowed_paths = {"./data"}
    );
    
    // Load from a directory (all .txt files)
    static security::Result<std::vector<Document>> load_text_directory(
        const std::string& dirpath,
        const std::vector<std::string>& allowed_paths = {"./data"}
    );
    
    // Load from a string
    static Document from_string(const std::string& content, const std::string& source = "string");
    // static security::Result<std::vector<Document>> from_json_array(const std::string& json_str);
    
    // Load from JSON
    static security::Result<Document> from_json_string(const std::string& json_str);
    
    // Load multiple JSON documents
    static security::Result<std::vector<Document>> from_json_array(const std::string& json_str);
};

} // namespace chaincpp::rag