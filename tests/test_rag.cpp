#include "chaincpp/rag/document.hpp"
#include "chaincpp/rag/embeddings.hpp"
#include "chaincpp/rag/vector_store.hpp"
#include "chaincpp/models/llm.hpp"
#include <iostream>

using namespace chaincpp::rag;
using namespace chaincpp::models;

void test_document_loading() {
    std::cout << "Testing Document loading...\n";
    
    // Test from string
    auto doc = DocumentLoader::from_string("Hello world", "test");
    assert(!doc.id.empty());
    assert(doc.page_content == "Hello world");
    std::cout << "  Document from string works\n";
    
    // Test to/from JSON
    auto json = doc.to_json();
    auto parsed = Document::from_json(json);
    assert(parsed.is_ok());
    assert(parsed.value().page_content == "Hello world");
    std::cout << "  JSON serialization works\n";
    
    std::cout << "Document tests passed\n\n";
}

void test_text_splitting() {
    std::cout << "Testing TextSplitter...\n";
    
    TextSplitter splitter;
    auto chunks = splitter.split_text("This is a test. This is another test.");
    assert(!chunks.empty());
    std::cout << "  Text split into " << chunks.size() << " chunks\n";
    
    // Test with a longer document
    std::string long_text = "This is a long text. " + std::string(500, 'A') + " More text.";
    auto long_chunks = splitter.split_text(long_text);
    assert(long_chunks.size() > 0);
    std::cout << "  Long text split into " << long_chunks.size() << " chunks\n";
    
    // Test document splitting
    Document doc;
    doc.page_content = "First paragraph. Second paragraph. Third paragraph.";
    auto doc_chunks = splitter.split_document(doc);
    assert(!doc_chunks.empty());
    std::cout << "  Document split into " << doc_chunks.size() << " chunks\n";
    
    std::cout << "TextSplitter tests passed\n\n";
}

void test_embeddings() {
    std::cout << "Testing Embeddings...\n";
    
    // Test local embeddings
    auto local_result = LocalEmbeddings::create({.dimension = 384});
    assert(local_result.is_ok());
    auto local = std::move(local_result.value());
    
    auto embed_result = local->embed("Hello world");
    assert(embed_result.is_ok());
    auto embedding = embed_result.value();
    assert(embedding.size() == 384);
    std::cout << "  Local embeddings dimension: " << embedding.size() << "\n";
    
    // Test batch embedding
    std::vector<std::string> texts = {"Hello", "World", "Test"};
    auto batch_result = local->embed_batch(texts);
    assert(batch_result.is_ok());
    auto batch = batch_result.value();
    assert(batch.size() == 3);
    std::cout << "  Batch embedding: " << batch.size() << " texts\n";
    
    std::cout << "Embeddings tests passed\n\n";
}

void test_vector_store() {
    std::cout << "Testing VectorStore...\n";
    
    auto store = InMemoryVectorStore::create();
    
    auto local = LocalEmbeddings::create({.dimension = 384}).value();
    
    // Add documents
    Document doc1;
    doc1.page_content = "The capital of France is Paris.";
    doc1.metadata["source"] = "test1";
    
    Document doc2;
    doc2.page_content = "The capital of Germany is Berlin.";
    doc2.metadata["source"] = "test2";
    
    auto add_result = store->add_document(doc1, *local);
    assert(add_result.is_ok());
    add_result = store->add_document(doc2, *local);
    assert(add_result.is_ok());
    
    assert(store->size() == 2);
    std::cout << "  Documents added: " << store->size() << "\n";
    
    // Search
    auto search_result = store->similarity_search_by_text("France", *local, 1);
    assert(search_result.is_ok());
    auto results = search_result.value();
    assert(!results.empty());
    assert(results[0].first.page_content.find("France") != std::string::npos);
    std::cout << "  Search found: " << results[0].first.page_content << "\n";
    std::cout << "  Similarity score: " << results[0].second << "\n";
    
    std::cout << "VectorStore tests passed\n\n";
}

void test_retrieval_chain() {
    std::cout << "Testing RetrievalChain...\n";
    
    auto store = InMemoryVectorStore::create();
    auto embedder = LocalEmbeddings::create({.dimension = 384}).value();
    
    // Try to create LLM
    auto llm_result = OpenAIChat::create();
    if (llm_result.is_err()) {
        std::cout << "  Skipping RetrievalChain test (no API key)\n\n";
        return;
    }
    
    auto chain_result = RetrievalChain::create(
        std::move(store),
        std::move(embedder),
        std::move(llm_result.value())
    );
    
    assert(chain_result.is_ok());
    std::cout << "  RetrievalChain created\n";
    
    // Add some documents
    std::vector<Document> docs = {
        DocumentLoader::from_string("Python is a programming language.", "python"),
        DocumentLoader::from_string("C++ is a powerful programming language.", "cpp"),
        DocumentLoader::from_string("Go is a language from Google.", "go")
    };
    
    auto add_result = chain_result.value()->add_documents(docs);
    assert(add_result.is_ok());
    std::cout << "  Documents added to chain\n";
    
    std::cout << "RetrievalChain tests passed\n\n";
}

int main() {
    std::cout << "\n========================================\n";
    std::cout << "chaincpp RAG Tests\n";
    std::cout << "========================================\n\n";
    
    test_document_loading();
    test_text_splitting();
    test_embeddings();
    test_vector_store();
    test_retrieval_chain();
    
    std::cout << "========================================\n";
    std::cout << "All RAG tests passed!\n";
    std::cout << "========================================\n\n";
    
    return 0;
}