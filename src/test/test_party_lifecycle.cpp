// MIT License

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "communication/transport.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "test_constants.h"
#include "utility/bit_vector.h"
#include "utility/config.h"

namespace {

using encrypto::motion::AccumulatedCommunicationStatistics;
using encrypto::motion::AccumulatedRunTimeStatistics;
using encrypto::motion::BitVector;
using encrypto::motion::Party;
using encrypto::motion::PrintStatistics;

constexpr auto kAesProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;
constexpr std::array<std::size_t, 4> kDefaultAesPartyCounts = {2, 3, 5, 10};
constexpr std::size_t kAesRounds = 10;
constexpr std::size_t kAesSimd = 1;
constexpr std::size_t kDefaultAesTrials = 2;

struct LifecycleBenchmarkResult {
  // Comparable total requested by the benchmark: sum of selected stage times.
  double total_ms{0.0};
  // End-to-end wall time, including cleanup effects.
  double wall_total_ms{0.0};
  double party_create_ms{0.0};
  double configure_ms{0.0};
  double round_run_ms{0.0};
  double reset_ms{0.0};
  double finish_ms{0.0};
  double cleanup_finish_ms{0.0};
  AccumulatedRunTimeStatistics run_time_statistics;
  AccumulatedCommunicationStatistics communication_statistics;
};

double ToMilliseconds(std::chrono::steady_clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

std::vector<std::size_t> ParsePositiveIntegers(const std::string& text) {
  std::vector<std::size_t> values;
  std::size_t current = 0;
  bool parsing_number = false;

  for (const auto character : text) {
    if (std::isdigit(static_cast<unsigned char>(character)) != 0) {
      current = current * 10 + static_cast<std::size_t>(character - '0');
      parsing_number = true;
    } else if (parsing_number) {
      if (current > 0) {
        values.push_back(current);
      }
      current = 0;
      parsing_number = false;
    }
  }

  if (parsing_number && current > 0) {
    values.push_back(current);
  }

  return values;
}

std::vector<std::size_t> GetAesPartyCounts() {
  if (const auto* env = std::getenv("MOTION_AES_PARTY_LIST"); env != nullptr) {
    const auto parsed = ParsePositiveIntegers(env);
    if (!parsed.empty()) {
      return parsed;
    }
  }
  return std::vector<std::size_t>(kDefaultAesPartyCounts.begin(), kDefaultAesPartyCounts.end());
}

std::size_t GetAesTrials() {
  if (const auto* env = std::getenv("MOTION_AES_TRIALS"); env != nullptr) {
    const auto parsed = ParsePositiveIntegers(env);
    if (!parsed.empty()) {
      return parsed.front();
    }
  }
  return kDefaultAesTrials;
}

double Median(std::vector<double> values) {
  if (values.empty()) {
    return 0.0;
  }

  std::sort(values.begin(), values.end());
  const auto middle = values.size() / 2;
  if ((values.size() % 2) == 1) {
    return values.at(middle);
  }
  return 0.5 * (values.at(middle - 1) + values.at(middle));
}

std::vector<double> CollectField(const std::vector<LifecycleBenchmarkResult>& results,
                                 double LifecycleBenchmarkResult::*field) {
  std::vector<double> values;
  values.reserve(results.size());
  for (const auto& result : results) {
    values.push_back(result.*field);
  }
  return values;
}

std::string CreateLfNormalizedAes128CircuitCopy() {
  const auto source_path = std::string(encrypto::motion::kRootDir) + "/circuits/advanced/aes_128.bristol";
  const auto target_path = std::string(encrypto::motion::kRootDir) + "/build/aes_128_lf_for_tests.bristol";

  std::ifstream source(source_path, std::ios::binary);
  if (!source.is_open()) {
    throw std::runtime_error("Cannot open AES128 Bristol circuit for test");
  }
  std::string content((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
  content.erase(std::remove(content.begin(), content.end(), '\r'), content.end());

  std::ofstream target(target_path, std::ios::binary | std::ios::trunc);
  if (!target.is_open()) {
    throw std::runtime_error("Cannot create normalized AES128 Bristol circuit copy for test");
  }
  target.write(content.data(), static_cast<std::streamsize>(content.size()));
  target.close();
  return target_path;
}

const encrypto::motion::AlgorithmDescription& GetAes128Algorithm() {
  static const auto kAesAlgorithm = [] {
    const auto normalized_path = CreateLfNormalizedAes128CircuitCopy();
    return encrypto::motion::AlgorithmDescription::FromBristol(normalized_path);
  }();
  return kAesAlgorithm;
}

void ConfigureParties(std::vector<std::unique_ptr<Party>>& parties) {
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
}

void ResetAllParties(std::vector<std::unique_ptr<Party>>& parties) {
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Reset(); }));
  }
  for (auto& future : futures) {
    future.get();
  }
}

void FinishAllParties(std::vector<std::unique_ptr<Party>>& parties) {
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Finish(); }));
  }
  for (auto& future : futures) {
    future.get();
  }
}

void AddTransportStatistics(encrypto::motion::communication::TransportStatistics& target,
                            const encrypto::motion::communication::TransportStatistics& source) {
  target.number_of_messages_sent += source.number_of_messages_sent;
  target.number_of_messages_received += source.number_of_messages_received;
  target.number_of_bytes_sent += source.number_of_bytes_sent;
  target.number_of_bytes_received += source.number_of_bytes_received;
}

void AccumulateRoundTransportStatistics(
    std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>&
        total_transport_statistics,
    const std::vector<std::unique_ptr<Party>>& parties) {
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    const auto round_statistics =
        parties.at(party_id)->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    if (total_transport_statistics.at(party_id).empty()) {
      total_transport_statistics.at(party_id) = round_statistics;
      continue;
    }

    if (total_transport_statistics.at(party_id).size() != round_statistics.size()) {
      throw std::runtime_error("Mismatching transport statistics sizes across rounds");
    }
    for (std::size_t i = 0; i < round_statistics.size(); ++i) {
      AddTransportStatistics(total_transport_statistics.at(party_id).at(i), round_statistics.at(i));
    }
  }
}

void CollectCommunicationStatisticsFromNestedVector(
    const std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>&
        transport_statistics,
    AccumulatedCommunicationStatistics& local_statistics,
    AccumulatedCommunicationStatistics* accumulated_statistics = nullptr) {
  for (const auto& statistics_by_peer : transport_statistics) {
    local_statistics.Add(statistics_by_peer);
    if (accumulated_statistics != nullptr) {
      accumulated_statistics->Add(statistics_by_peer);
    }
  }
}

void RunAes128RoundAndCollectRunTime(
    std::vector<std::unique_ptr<Party>>& parties, std::size_t round,
    AccumulatedRunTimeStatistics& run_time_statistics,
    AccumulatedRunTimeStatistics* accumulated_run_time_statistics = nullptr) {
  std::vector<encrypto::motion::ShareWrapper> outputs(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    std::vector<BitVector<>> local_input(256, BitVector<>(kAesSimd, false));
    if (party_id == 0) {
      for (std::size_t i = 0; i < local_input.size(); ++i) {
        local_input[i] = BitVector<>(kAesSimd, ((i + round) % 2) == 1);
      }
    }

    encrypto::motion::ShareWrapper input_share(
        parties.at(party_id)->In<kAesProtocol>(std::move(local_input), 0));
    auto aes_output = input_share.Evaluate(GetAes128Algorithm());
    outputs.at(party_id) = aes_output.Out(0);
  }

  std::vector<BitVector<>> opened_output;
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, &parties, &outputs, &opened_output] {
      auto& party = parties.at(party_id);
      party->Run();
      if (party_id == 0) {
        opened_output = outputs.at(party_id).As<std::vector<BitVector<>>>();
      }
    }));
  }
  for (auto& future : futures) {
    future.get();
  }

  ASSERT_EQ(opened_output.size(), 128u);

  for (auto& party : parties) {
    const auto& runs = party->GetBackend()->GetRunTimeStatistics();
    ASSERT_FALSE(runs.empty());
    run_time_statistics.Add(runs.back());
    if (accumulated_run_time_statistics != nullptr) {
      accumulated_run_time_statistics->Add(runs.back());
    }
  }
}

LifecycleBenchmarkResult BenchmarkAes128UsingReset(
    std::size_t number_of_parties,
    AccumulatedRunTimeStatistics* accumulated_run_time_statistics = nullptr,
    AccumulatedCommunicationStatistics* accumulated_communication_statistics = nullptr) {
  LifecycleBenchmarkResult result;
  const auto wall_total_start = std::chrono::steady_clock::now();

  auto stage_start = std::chrono::steady_clock::now();
  auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
  result.party_create_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  stage_start = std::chrono::steady_clock::now();
  ConfigureParties(parties);
  result.configure_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  for (std::size_t round = 0; round < kAesRounds; ++round) {
    stage_start = std::chrono::steady_clock::now();
    RunAes128RoundAndCollectRunTime(parties, round, result.run_time_statistics,
                                    accumulated_run_time_statistics);
    result.round_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ResetAllParties(parties);
    result.reset_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);
  }

  std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>
      total_transport_statistics(number_of_parties);
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    total_transport_statistics.at(party_id) =
        parties.at(party_id)->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
  }

  // Cleanup is intentionally excluded from comparable total_ms.
  stage_start = std::chrono::steady_clock::now();
  FinishAllParties(parties);
  result.cleanup_finish_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  CollectCommunicationStatisticsFromNestedVector(total_transport_statistics,
                                                 result.communication_statistics,
                                                 accumulated_communication_statistics);

  result.total_ms = result.party_create_ms + result.configure_ms + result.round_run_ms + result.reset_ms;
  result.wall_total_ms = ToMilliseconds(std::chrono::steady_clock::now() - wall_total_start);
  return result;
}

LifecycleBenchmarkResult BenchmarkAes128UsingFinish(
    std::size_t number_of_parties,
    AccumulatedRunTimeStatistics* accumulated_run_time_statistics = nullptr,
    AccumulatedCommunicationStatistics* accumulated_communication_statistics = nullptr) {
  LifecycleBenchmarkResult result;
  const auto wall_total_start = std::chrono::steady_clock::now();

  std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>
      total_transport_statistics(number_of_parties);

  for (std::size_t round = 0; round < kAesRounds; ++round) {
    auto stage_start = std::chrono::steady_clock::now();
    auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
    result.party_create_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ConfigureParties(parties);
    result.configure_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    RunAes128RoundAndCollectRunTime(parties, round, result.run_time_statistics,
                                    accumulated_run_time_statistics);
    result.round_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    FinishAllParties(parties);
    result.finish_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    AccumulateRoundTransportStatistics(total_transport_statistics, parties);
  }

  CollectCommunicationStatisticsFromNestedVector(total_transport_statistics,
                                                 result.communication_statistics,
                                                 accumulated_communication_statistics);

  result.total_ms = result.party_create_ms + result.configure_ms + result.round_run_ms + result.finish_ms;
  result.wall_total_ms = ToMilliseconds(std::chrono::steady_clock::now() - wall_total_start);
  return result;
}

TEST(Aes128ResetFinish, Aes128ResetVsFinishTotalTime_10Rounds_2_3_5_10Parties) {
  const auto party_counts = GetAesPartyCounts();
  const auto trial_count = GetAesTrials();

  ASSERT_GT(trial_count, 0u);

  for (const auto number_of_parties : party_counts) {
    std::vector<LifecycleBenchmarkResult> reset_results;
    std::vector<LifecycleBenchmarkResult> finish_results;
    reset_results.reserve(trial_count);
    finish_results.reserve(trial_count);

    AccumulatedRunTimeStatistics reset_accumulated_run_time_statistics;
    AccumulatedRunTimeStatistics finish_accumulated_run_time_statistics;
    AccumulatedCommunicationStatistics reset_accumulated_communication_statistics;
    AccumulatedCommunicationStatistics finish_accumulated_communication_statistics;

    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto run_reset = [&] {
        reset_results.emplace_back(BenchmarkAes128UsingReset(
            number_of_parties, &reset_accumulated_run_time_statistics,
            &reset_accumulated_communication_statistics));
      };
      const auto run_finish = [&] {
        finish_results.emplace_back(BenchmarkAes128UsingFinish(
            number_of_parties, &finish_accumulated_run_time_statistics,
            &finish_accumulated_communication_statistics));
      };

      if ((trial % 2) == 0) {
        run_reset();
        run_finish();
      } else {
        run_finish();
        run_reset();
      }
    }

    const auto reset_name = "AES128 Create+Configure+(Run+Reset)x10 (" + std::to_string(number_of_parties) +
                            " parties, " + std::to_string(kAesRounds) +
                            " rounds, " + std::to_string(trial_count) + " trials, interleaved)";
    const auto finish_name = "AES128 Create+Configure+Run+Finish (" + std::to_string(number_of_parties) +
                             " parties, " + std::to_string(kAesRounds) +
                             " rounds, " + std::to_string(trial_count) + " trials, interleaved)";

    std::cout << PrintStatistics(reset_name, reset_accumulated_run_time_statistics,
                                 reset_accumulated_communication_statistics);
    std::cout << PrintStatistics(finish_name, finish_accumulated_run_time_statistics,
                                 finish_accumulated_communication_statistics);

    const auto reset_total_median = Median(CollectField(reset_results, &LifecycleBenchmarkResult::total_ms));
    const auto finish_total_median =
        Median(CollectField(finish_results, &LifecycleBenchmarkResult::total_ms));
    const auto ratio = finish_total_median > 0.0 ? (reset_total_median / finish_total_median) : 0.0;

    const auto reset_wall_total_median =
        Median(CollectField(reset_results, &LifecycleBenchmarkResult::wall_total_ms));
    const auto finish_wall_total_median =
        Median(CollectField(finish_results, &LifecycleBenchmarkResult::wall_total_ms));

    const auto reset_create_median =
        Median(CollectField(reset_results, &LifecycleBenchmarkResult::party_create_ms));
    const auto reset_configure_median =
        Median(CollectField(reset_results, &LifecycleBenchmarkResult::configure_ms));
    const auto reset_run_median =
        Median(CollectField(reset_results, &LifecycleBenchmarkResult::round_run_ms));
    const auto reset_reset_median =
        Median(CollectField(reset_results, &LifecycleBenchmarkResult::reset_ms));
    const auto reset_cleanup_finish_median =
        Median(CollectField(reset_results, &LifecycleBenchmarkResult::cleanup_finish_ms));

    const auto finish_create_median =
        Median(CollectField(finish_results, &LifecycleBenchmarkResult::party_create_ms));
    const auto finish_configure_median =
        Median(CollectField(finish_results, &LifecycleBenchmarkResult::configure_ms));
    const auto finish_run_median =
        Median(CollectField(finish_results, &LifecycleBenchmarkResult::round_run_ms));
    const auto finish_finish_median =
        Median(CollectField(finish_results, &LifecycleBenchmarkResult::finish_ms));

    std::cout << "AES128 comparable total median (ms): parties=" << number_of_parties
              << ", rounds=" << kAesRounds << ", trials=" << trial_count
              << ", reset_total_median=" << reset_total_median
              << ", finish_total_median=" << finish_total_median << ", reset/finish=" << ratio
              << "\n";

    std::cout << "AES128 wall total median (ms): parties=" << number_of_parties
              << ", reset_wall_total_median=" << reset_wall_total_median
              << ", finish_wall_total_median=" << finish_wall_total_median << "\n";

    std::cout << "AES128 stage medians reset(ms): create=" << reset_create_median
              << ", configure=" << reset_configure_median << ", run=" << reset_run_median
              << ", reset=" << reset_reset_median
              << ", cleanup_finish(excluded)=" << reset_cleanup_finish_median << "\n";

    std::cout << "AES128 stage medians finish(ms): create=" << finish_create_median
              << ", configure=" << finish_configure_median << ", run=" << finish_run_median
              << ", finish=" << finish_finish_median << "\n";

    EXPECT_GT(reset_total_median, 0.0);
    EXPECT_GT(finish_total_median, 0.0);
  }
}

}  // namespace

