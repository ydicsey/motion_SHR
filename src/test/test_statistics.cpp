// MIT License

#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "communication/transport.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"

namespace {

using encrypto::motion::AccumulatedCommunicationStatistics;
using encrypto::motion::AccumulatedRunTimeStatistics;
using encrypto::motion::RunTimeStatistics;
using encrypto::motion::communication::Transport;
using encrypto::motion::communication::TransportStatistics;

class TestTransport final : public Transport {
 public:
  void SendMessage(std::span<const std::uint8_t>) override {}
  bool Available() const override { return false; }
  std::optional<std::vector<std::uint8_t>> ReceiveMessage() override { return std::nullopt; }
  void ShutdownSend() override {}
  void Shutdown() override {}

  TransportStatistics& MutableStatistics() { return statistics_; }
};

}  // namespace

TEST(Statistics, RunTimeSynchronizationDurationIsPrintableAndResettable) {
  using StatId = RunTimeStatistics::StatisticsId;

  RunTimeStatistics statistics;
  statistics.AddDuration<StatId::kSynchronize>(std::chrono::milliseconds(3));
  statistics.AddDuration<StatId::kSynchronize>(std::chrono::milliseconds(4));

  EXPECT_EQ(statistics.GetDuration(StatId::kSynchronize), std::chrono::milliseconds(7));
  EXPECT_NE(statistics.PrintHumanReadable().find("Synchronization"), std::string::npos);

  statistics.Reset();
  EXPECT_EQ(statistics.GetDuration(StatId::kSynchronize), RunTimeStatistics::Duration::zero());
}

TEST(Statistics, AccumulatedRunTimeStatisticsIncludesSynchronizationInOutputAndJson) {
  using StatId = RunTimeStatistics::StatisticsId;

  RunTimeStatistics first;
  first.AddDuration<StatId::kSynchronize>(std::chrono::milliseconds(3));
  RunTimeStatistics second;
  second.AddDuration<StatId::kSynchronize>(std::chrono::milliseconds(7));

  AccumulatedRunTimeStatistics accumulated;
  accumulated.Add(first);
  accumulated.Add(second);

  const auto text = accumulated.PrintHumanReadable();
  EXPECT_NE(text.find("Synchronization"), std::string::npos);

  const auto json = accumulated.ToJson();
  ASSERT_TRUE(json.contains("synchronization"));
  const auto& synchronization = json.at("synchronization").as_object();
  EXPECT_NEAR(synchronization.at("mean").as_double(), 5.0, 0.001);
  EXPECT_NEAR(synchronization.at("median").as_double(), 5.0, 0.001);
  EXPECT_NEAR(synchronization.at("sum").as_double(), 10.0, 0.001);
}

TEST(Statistics, AccumulatedCommunicationStatisticsUsesMessageAndByteMeans) {
  TransportStatistics first;
  first.number_of_messages_sent = 2;
  first.number_of_messages_received = 4;
  first.number_of_bytes_sent = 1024;
  first.number_of_bytes_received = 2048;

  TransportStatistics second;
  second.number_of_messages_sent = 6;
  second.number_of_messages_received = 8;
  second.number_of_bytes_sent = 3072;
  second.number_of_bytes_received = 4096;

  AccumulatedCommunicationStatistics accumulated;
  accumulated.Add(first);
  accumulated.Add(second);

  const auto text = accumulated.PrintHumanReadable();
  EXPECT_NE(text.find("Sent:"), std::string::npos);
  EXPECT_NE(text.find("Received:"), std::string::npos);

  const auto json = accumulated.ToJson();
  EXPECT_EQ(json.at("num_messages_sent").as_uint64(), 4u);
  EXPECT_EQ(json.at("num_messages_received").as_uint64(), 6u);
  EXPECT_EQ(json.at("bytes_sent").as_uint64(), 2048u);
  EXPECT_EQ(json.at("bytes_received").as_uint64(), 3072u);
}

TEST(Statistics, TransportResetStatisticsClearsTcpTimingFields) {
  TestTransport transport;
  auto& statistics = transport.MutableStatistics();
  statistics.number_of_messages_sent = 1;
  statistics.number_of_messages_received = 2;
  statistics.number_of_bytes_sent = 3;
  statistics.number_of_bytes_received = 4;
  statistics.send_time_ns = 5;
  statistics.receive_time_ns = 6;
  statistics.receive_wait_time_ns = 7;
  statistics.receive_message_size_time_ns = 8;
  statistics.receive_payload_time_ns = 9;

  transport.ResetStatistics();
  const auto& reset_statistics = transport.GetStatistics();
  EXPECT_EQ(reset_statistics.number_of_messages_sent, 0u);
  EXPECT_EQ(reset_statistics.number_of_messages_received, 0u);
  EXPECT_EQ(reset_statistics.number_of_bytes_sent, 0u);
  EXPECT_EQ(reset_statistics.number_of_bytes_received, 0u);
  EXPECT_EQ(reset_statistics.send_time_ns, 0u);
  EXPECT_EQ(reset_statistics.receive_time_ns, 0u);
  EXPECT_EQ(reset_statistics.receive_wait_time_ns, 0u);
  EXPECT_EQ(reset_statistics.receive_message_size_time_ns, 0u);
  EXPECT_EQ(reset_statistics.receive_payload_time_ns, 0u);
}
