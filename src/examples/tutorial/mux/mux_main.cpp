// MIT License
//
// Copyright (c) 2026
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <cstdint>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <tuple>
#include <vector>

#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "base/party.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "protocols/share_wrapper.h"
#include "utility/bit_vector.h"

namespace program_options = boost::program_options;

bool CheckPartyArgumentSyntax(const std::string& party_argument);
std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string& party_argument);
std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]);
encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options);
void RunBooleanGmwMuxDemo(encrypto::motion::PartyPointer& party, bool print_output);

int main(int ac, char* av[]) {
  try {
    auto [user_options, help_flag] = ParseProgramOptions(ac, av);
    if (help_flag) return EXIT_SUCCESS;

    auto party = CreateParty(user_options);
    RunBooleanGmwMuxDemo(party, user_options["print-output"].as<bool>());
    return EXIT_SUCCESS;
  } catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
}

const std::regex kPartyArgumentRegex("(\\d+),([^,]+),(\\d{1,5})");

bool CheckPartyArgumentSyntax(const std::string& party_argument) {
  return std::regex_match(party_argument, kPartyArgumentRegex);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string& party_argument) {
  std::smatch match;
  std::regex_match(party_argument, match, kPartyArgumentRegex);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  constexpr std::string_view kConfigFileMessage =
      "configuration file, other arguments will overwrite the parameters read from the configuration file"sv;

  bool print = false;
  bool help = false;
  program_options::options_description description("Allowed options");
  // clang-format off
  description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false), "produce help message")
      ("disable-logging,l", "disable logging to file")
      ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
      ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "info (id,host,port) for each party, e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("online-after-setup", program_options::value<bool>()->default_value(true), "compute online phase after setup phase is done (true/1 or false/0)")
      ("print-output", program_options::value<bool>()->default_value(true), "print reconstructed output values");
  // clang-format on

  program_options::variables_map user_options;
  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);

  if (help || ac == 1) {
    std::cout << description << "\n";
    return std::make_pair<program_options::variables_map, bool>({}, true);
  }

  if (user_options.count("configuration-file")) {
    std::ifstream options_file(user_options["configuration-file"].as<std::string>().c_str());
    program_options::store(program_options::parse_config_file(options_file, description),
                           user_options);
    program_options::notify(user_options);
  }

  if (!user_options.count("my-id")) {
    throw std::runtime_error("My id is not set but required");
  }
  if (!user_options.count("parties")) {
    throw std::runtime_error("Other parties' information is not set but required");
  }

  const auto parties = user_options["parties"].as<std::vector<std::string>>();
  for (const auto& party : parties) {
    if (!CheckPartyArgumentSyntax(party)) {
      throw std::runtime_error("Incorrect party argument syntax: " + party);
    }
  }

  if (print) {
    std::cout << "My id " << user_options["my-id"].as<std::size_t>() << std::endl;
    std::cout << "Other parties:";
    for (const auto& party : parties) {
      std::cout << " " << party;
    }
    std::cout << std::endl;
  }

  return std::make_pair(user_options, false);
}

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options) {
  const auto parties_string = user_options["parties"].as<const std::vector<std::string>>();
  const auto number_of_parties = parties_string.size();
  const auto my_id = user_options["my-id"].as<std::size_t>();

  if (my_id >= number_of_parties) {
    throw std::runtime_error(fmt::format(
        "My id needs to be in [0, #parties - 1], current my id is {} and #parties is {}", my_id,
        number_of_parties));
  }

  encrypto::motion::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);
  for (const auto& party_string : parties_string) {
    const auto [party_id, host, port] = ParsePartyArgument(party_string);
    if (party_id >= number_of_parties) {
      throw std::runtime_error(fmt::format(
          "Party id needs to be in [0, #parties - 1], current id is {} and #parties is {}",
          party_id, number_of_parties));
    }
    parties_configuration.at(party_id) = std::make_pair(host, port);
  }

  encrypto::motion::communication::TcpSetupHelper helper(my_id, parties_configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(
      my_id, helper.SetupConnections());
  auto party = std::make_unique<encrypto::motion::Party>(std::move(communication_layer));

  const auto configuration = party->GetConfiguration();
  configuration->SetLoggingEnabled(!user_options.count("disable-logging"));
  configuration->SetOnlineAfterSetup(user_options["online-after-setup"].as<bool>());

  return party;
}

void RunBooleanGmwMuxDemo(encrypto::motion::PartyPointer& party, bool print_output) {
  using encrypto::motion::BitVector;
  using encrypto::motion::MpcProtocol;

  constexpr auto kProtocol = MpcProtocol::kBooleanGmw;
  constexpr std::size_t kSimd = 4;

  const auto my_id = party->GetConfiguration()->GetMyId();
  const auto number_of_parties = party->GetConfiguration()->GetNumOfParties();

  const std::size_t a_owner = 0;
  const std::size_t b_owner = number_of_parties > 1 ? 1 : 0;
  const std::size_t selection_owner = 0;

  std::vector<std::uint64_t> dummy_values(kSimd, 0);
  BitVector<> dummy_selection(kSimd, false);

  auto evaluate_round = [&](const std::vector<std::uint64_t>& a_values,
                            const std::vector<std::uint64_t>& b_values,
                            const BitVector<>& selection_values, const std::string& round_name) {
    const auto a_input = my_id == a_owner ? encrypto::motion::ToInput(a_values)
                                          : encrypto::motion::ToInput(dummy_values);
    const auto b_input = my_id == b_owner ? encrypto::motion::ToInput(b_values)
                                          : encrypto::motion::ToInput(dummy_values);
    const auto selection_input = my_id == selection_owner ? selection_values : dummy_selection;

    encrypto::motion::ShareWrapper shared_a = party->In<kProtocol>(a_input, a_owner);
    encrypto::motion::ShareWrapper shared_b = party->In<kProtocol>(b_input, b_owner);
    encrypto::motion::ShareWrapper shared_selection =
        party->In<kProtocol>(selection_input, selection_owner);

    auto shared_output = shared_selection.Mux(shared_a, shared_b).Out();

    party->Run();

    const auto output_bits = shared_output.As<std::vector<BitVector<>>>();
    const auto output_values = encrypto::motion::ToVectorOutput<std::uint64_t>(output_bits);

    for (std::size_t i = 0; i < kSimd; ++i) {
      const auto expected = selection_values.Get(i) ? a_values[i] : b_values[i];
      if (output_values[i] != expected) {
        throw std::runtime_error(fmt::format(
            "{} failed at SIMD index {}: expected {}, got {}", round_name, i, expected,
            output_values[i]));
      }
    }

    if (print_output && my_id == 0) {
      std::cout << "BooleanGMW MUX demo " << round_name << " (sel ? a : b)" << std::endl;
      std::cout << "index\tsel\ta\tb\tout" << std::endl;
      for (std::size_t i = 0; i < kSimd; ++i) {
        std::cout << i << "\t" << static_cast<std::uint32_t>(selection_values.Get(i)) << "\t"
                  << a_values[i] << "\t" << b_values[i] << "\t" << output_values[i]
                  << std::endl;
      }
    }
  };

  const std::vector<std::uint64_t> round1_a{10, 20, 30, 40};
  const std::vector<std::uint64_t> round1_b{100, 200, 300, 400};
  BitVector<> round1_selection(kSimd, false);
  round1_selection.Set(true, 0);
  round1_selection.Set(true, 2);

  const std::vector<std::uint64_t> round2_a{11, 22, 33, 44};
  const std::vector<std::uint64_t> round2_b{101, 202, 303, 404};
  BitVector<> round2_selection(kSimd, false);
  round2_selection.Set(true, 1);
  round2_selection.Set(true, 3);

  evaluate_round(round1_a, round1_b, round1_selection, "round1-before-reset");

  if (print_output && my_id == 0) {
    std::cout << "Reset party and run MUX again..." << std::endl;
  }

  party->Reset();

  evaluate_round(round2_a, round2_b, round2_selection, "round2-after-reset");

  if (print_output && my_id == 0) {
    std::cout << "MUX works after party->Reset()." << std::endl;
  }

  party->Finish();
}
