// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
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

#include "algorithm_description.h"

#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>
#include <unordered_map>

#include <fmt/format.h>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

namespace encrypto::motion {

AlgorithmDescription AlgorithmDescription::FromBristol(const std::string& path) {
  std::ifstream file_stream(path);
  return FromBristol(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristol(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromBristol(file_stream);
}

//
// Bristol format
// 49 65            *** total # of gates, total # of wires
// 8 8 8            *** # input wires parent a, # input wires parent b, # of output wires
//                  *** empty line
// *** below, only gate-related infos:
// *** # of input shares (bundled wires, i.e., XOR has 2 inputs, INV 1, and MUX 3),
// *** # of outputs,
// *** input wire ids (1--many)
// *** output wire ids (usually 1)
// *** gate type
// 2 1 0 8 57 XOR
// 2 1 1 9 16 XOR   ***
// 2 1 0 8 17 AND   ***
// ...
//

AlgorithmDescription AlgorithmDescription::FromBristol(std::ifstream& stream) {
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());
  stream >> algorithm_description.number_of_gates >> algorithm_description.number_of_wires;
  algorithm_description.constant_wires.assign(algorithm_description.number_of_wires,
                                              std::nullopt);

  std::vector<std::string> line_vector;
  std::string line;
  std::getline(stream, line);  // skip \n at the end of the first line
  // second line
  {
    std::string second_line;
    std::getline(stream, second_line);
    std::stringstream ss(second_line);
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
      line.clear();
    }
    algorithm_description.number_of_input_wires_parent_a = std::stoull(line_vector.at(0));
    if (line_vector.size() == 2) {
      algorithm_description.number_of_output_wires = std::stoull(line_vector.at(1));
    } else if (line_vector.size() == 3) {
      algorithm_description.number_of_input_wires_parent_b = std::stoull(line_vector.at(1));
      algorithm_description.number_of_output_wires = std::stoull(line_vector.at(2));
    } else {
      throw std::runtime_error(
          std::string("Unexpected number of values: " + std::to_string(line_vector.size()) + "\n"));
    }
    line.clear();
    line_vector.clear();
  }

  std::getline(stream, line);
  assert(line.empty());

  // read line
  const auto reverse_chunks = [](std::vector<long long>& ids, std::size_t chunk) {
    if (chunk == 0 || ids.empty() || ids.size() % chunk != 0) return;
    for (std::size_t offset = 0; offset < ids.size(); offset += chunk) {
      std::reverse(ids.begin() + offset, ids.begin() + offset + chunk);
    }
  };

  while (std::getline(stream, line)) {
    std::stringstream ss(line);
    // split line
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
    }

    if (line_vector.empty()) continue;
    const auto& type = line_vector.at(line_vector.size() - 1);
    PrimitiveOperation primitive_operation;
    if (type == std::string("XOR") || type == std::string("AND") || type == std::string("ADD") ||
        type == std::string("MUL") || type == std::string("OR")) {
      assert(line_vector.size() == 6);
      if (type == std::string("XOR"))
        primitive_operation.type = PrimitiveOperationType::kXor;
      else if (type == std::string("AND"))
        primitive_operation.type = PrimitiveOperationType::kAnd;
      else if (type == std::string("ADD"))
        primitive_operation.type = PrimitiveOperationType::kAdd;
      else if (type == std::string("MUL"))
        primitive_operation.type = PrimitiveOperationType::kMul;
      else if (type == std::string("OR"))
        primitive_operation.type = PrimitiveOperationType::kOr;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.parent_b = std::stoull(line_vector.at(3));
      primitive_operation.output_wire = std::stoull(line_vector.at(4));
    } else if (type == std::string("MUX")) {
      assert(line_vector.size() == 7);
      primitive_operation.type = PrimitiveOperationType::kMux;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.parent_b = std::stoull(line_vector.at(3));
      primitive_operation.selection_bit = std::stoull(line_vector.at(4));
      primitive_operation.output_wire = std::stoull(line_vector.at(5));
    } else if (type == std::string("INV")) {
      assert(line_vector.size() == 5);
      primitive_operation.type = PrimitiveOperationType::kInv;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.output_wire = std::stoull(line_vector.at(3));
    } else {
      throw std::runtime_error("Unknown operation type: " + line_vector.at(line_vector.size() - 1) +
                               "\n");
    }
    algorithm_description.gates.emplace_back(primitive_operation);
    line.clear();
    line_vector.clear();
  }
  // Default output ordering: last number_of_output_wires wires.
  for (std::size_t i = algorithm_description.number_of_wires -
                          algorithm_description.number_of_output_wires;
       i < algorithm_description.number_of_wires; ++i) {
    algorithm_description.output_wire_indices.push_back(i);
  }

  return algorithm_description;
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(const std::string& path) {
  std::ifstream file_stream(path);
  return FromBristolFashion(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromBristolFashion(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(std::ifstream& stream) {
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());

  constexpr std::size_t kGateEncodingLineNumber = 4;
  const static std::regex kLineTwoNumbersRegex("^\\s*(\\d+)\\s+(\\d+)\\s*$");
  const static std::regex kLineThreeNumbersRegex("^\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*$");
  const static std::regex kLineGateRegex(
      "^\\s*(1|2)\\s+(1)\\s+(\\d+)\\s+(\\d+\\s+)?(\\d+)\\s+(XOR|AND|INV)\\s*$");
  const static std::regex kLineWhitespaceRegex("^\\s*$");

  std::string line;
  std::smatch match;

  // first line
  std::getline(stream, line);
  if (!std::regex_match(line, match, kLineTwoNumbersRegex)) {
    throw std::runtime_error("Cannot parse Bristol Fashion file at line 1");
  }
  algorithm_description.number_of_gates = boost::lexical_cast<std::size_t>(match[1]);
  algorithm_description.number_of_wires = boost::lexical_cast<std::size_t>(match[2]);

  // second line
  std::getline(stream, line);
  if (std::regex_match(line, match, kLineTwoNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 1) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 2");
    }
    algorithm_description.number_of_input_wires_parent_a =
        boost::lexical_cast<std::size_t>(match[2]);
  } else if (std::regex_match(line, match, kLineThreeNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 2) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 2");
    }
    algorithm_description.number_of_input_wires_parent_a =
        boost::lexical_cast<std::size_t>(match[2]);
    algorithm_description.number_of_input_wires_parent_b =
        boost::lexical_cast<std::size_t>(match[3]);
  } else {
    throw std::runtime_error(
        "Cannot parse Bristol Fashion file at line 2 (maybe unsupported number of input values)");
  }

  // third line
  std::getline(stream, line);
  if (std::regex_match(line, match, kLineTwoNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 1) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 3");
    }
    algorithm_description.number_of_output_wires = boost::lexical_cast<std::size_t>(match[2]);
  } else {
    throw std::runtime_error(
        "Cannot parse Bristol Fashion file at line 3 (maybe unsupported number of output values)");
  }

  // consume empty line
  std::getline(stream, line);
  assert(line.empty());

  std::size_t line_number = kGateEncodingLineNumber;

  // read gates
  while (std::getline(stream, line)) {
    ++line_number;
    if (line.empty() || std::regex_match(line, kLineWhitespaceRegex)) {
      continue;
    }

    if (!std::regex_match(line, match, kLineGateRegex)) {
      throw std::runtime_error(
          fmt::format("Cannot parse Bristol Fashion file at line {}", line_number));
    }

    using namespace std::string_literals;

    auto number_of_inputs = boost::lexical_cast<std::size_t>(match[1]);
    const auto& operation = match[6];
    PrimitiveOperation primitive_operation;

    if (operation == "XOR"s) {
      if (number_of_inputs != 2) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kXor;
    } else if (operation == "AND"s) {
      if (number_of_inputs != 2) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kAnd;
    } else if (operation == "INV"s) {
      if (number_of_inputs != 1) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kInv;
    }
    primitive_operation.output_wire = boost::lexical_cast<std::size_t>(match[5]);
    primitive_operation.parent_a = boost::lexical_cast<std::size_t>(match[3]);
    if (number_of_inputs == 2) {
      std::string input_b = match[4];
      boost::trim(input_b);
      primitive_operation.parent_b = boost::lexical_cast<std::size_t>(input_b);
    }
    algorithm_description.gates.emplace_back(std::move(primitive_operation));
  }

  algorithm_description.constant_wires.assign(algorithm_description.number_of_wires,
                                              std::nullopt);
  // Default output ordering: last number_of_output_wires wires.
  for (std::size_t i = algorithm_description.number_of_wires -
                          algorithm_description.number_of_output_wires;
       i < algorithm_description.number_of_wires; ++i) {
    algorithm_description.output_wire_indices.push_back(i);
  }

  return algorithm_description;
}

AlgorithmDescription AlgorithmDescription::FromAby(const std::string& path) {
  std::ifstream file_stream(path);
  return FromAby(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromAby(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromAby(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromAby(std::ifstream& stream) {
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());
  std::string line;
  std::size_t server_inputs = 0, client_inputs = 0;
  std::size_t next_wire_id = 0;
  std::unordered_map<long long, std::size_t> wire_map;
  std::unordered_map<long long, bool> const_map;

  const auto map_wire = [&](long long external_id) -> std::size_t {
    auto it = wire_map.find(external_id);
    if (it != wire_map.end()) return it->second;
    auto id = next_wire_id++;
    wire_map.emplace(external_id, id);
    return id;
  };

  const auto get_const = [&](long long external_id) -> std::optional<bool> {
    auto it = const_map.find(external_id);
    if (it == const_map.end()) return std::nullopt;
    return it->second;
  };

  auto add_gate = [&](PrimitiveOperation gate) -> std::size_t {
    gate.output_wire = next_wire_id++;
    algorithm_description.gates.emplace_back(std::move(gate));
    return gate.output_wire;
  };

  // Reverse IDs within fixed-size chunks (e.g., 64-bit words) to flip MSB->LSB order per value.
  const auto reverse_chunks = [](std::vector<long long>& ids, std::size_t chunk) {
    if (chunk == 0 || ids.empty() || ids.size() % chunk != 0) return;
    for (std::size_t offset = 0; offset < ids.size(); offset += chunk) {
      std::reverse(ids.begin() + offset, ids.begin() + offset + chunk);
    }
  };

  while (std::getline(stream, line)) {
    boost::algorithm::trim(line);
    if (line.empty()) {
      continue;
    }

    const char identifier = line.front();
    if (identifier == '#') {
      continue;  // comment line
    }

    std::stringstream ss(line);
    ss >> std::ws;  // drop potential leading whitespace

    switch (identifier) {
      case 'C': {
        char tag;
        ss >> tag;
        if (tag != 'C') {
          throw std::runtime_error("Malformed client input declaration in ABY file");
        }
        std::vector<long long> wire_ids;
        long long wire_id = 0;
        while (ss >> wire_id) {
          wire_ids.push_back(wire_id);
        }
        client_inputs += wire_ids.size();
        // ABY lists input bits MSB->LSB per value; reverse within 64-bit chunks to get LSB->MSB.
        reverse_chunks(wire_ids, 64);
        for (auto id : wire_ids) {
          map_wire(id);
        }
        break;
      }
      case 'S': {
        char tag;
        ss >> tag;
        if (tag != 'S') {
          throw std::runtime_error("Malformed server input declaration in ABY file");
        }
        std::vector<long long> wire_ids;
        long long wire_id = 0;
        while (ss >> wire_id) {
          wire_ids.push_back(wire_id);
        }
        server_inputs += wire_ids.size();
        // ABY lists input bits MSB->LSB per value; reverse within 64-bit chunks to get LSB->MSB.
        reverse_chunks(wire_ids, 64);
        for (auto id : wire_ids) {
          map_wire(id);
        }
        break;
      }
      case 'O': {
        char tag;
        ss >> tag;
        if (tag != 'O') {
          throw std::runtime_error("Malformed output declaration in ABY file");
        }
        std::vector<long long> wire_ids;
        long long wire_id = 0;
        while (ss >> wire_id) {
          wire_ids.push_back(wire_id);
        }
        // Keep outputs LSB->MSB per 64-bit value to match internal packing.
        reverse_chunks(wire_ids, 64);
        algorithm_description.number_of_output_wires += wire_ids.size();
        for (auto id : wire_ids) {
          algorithm_description.output_wire_indices.push_back(map_wire(id));
        }
        break;
      }
      case '0':
      case '1': {
        char tag;
        ss >> tag;
        if (tag != '0' && tag != '1') {
          throw std::runtime_error("Malformed constant declaration in ABY file");
        }
        long long wire_id = 0;
        if (!(ss >> wire_id)) {
          throw std::runtime_error("Malformed constant declaration in ABY file");
        }
        map_wire(wire_id);
        const_map[wire_id] = (identifier == '1');
        break;
      }
      case 'A':
      case 'X':
      case 'V': {
        char tag;
        ss >> tag;
        long long in0_ext = 0, in1_ext = 0, out_ext = 0;
        if (!(ss >> in0_ext >> in1_ext >> out_ext)) {
          throw std::runtime_error("Malformed binary gate definition in ABY file");
        }

        const auto c0 = get_const(in0_ext);
        const auto c1 = get_const(in1_ext);
        const auto w0 = c0 ? std::nullopt : std::optional<std::size_t>(map_wire(in0_ext));
        const auto w1 = c1 ? std::nullopt : std::optional<std::size_t>(map_wire(in1_ext));

        // Constant folding where possible
        if (identifier == 'X') {
          if (c0 && c1) {
            map_wire(out_ext);
            const_map[out_ext] = *c0 ^ *c1;
            break;
          }
          if (c0 && *c0 == false) {
            wire_map[out_ext] = w1.value();
            break;
          }
          if (c1 && *c1 == false) {
            wire_map[out_ext] = w0.value();
            break;
          }
          if (c0 && *c0 == true) {
            PrimitiveOperation gate;
            gate.type = PrimitiveOperationType::kInv;
            gate.parent_a = w1.value();
            wire_map[out_ext] = add_gate(gate);
            break;
          }
          if (c1 && *c1 == true) {
            PrimitiveOperation gate;
            gate.type = PrimitiveOperationType::kInv;
            gate.parent_a = w0.value();
            wire_map[out_ext] = add_gate(gate);
            break;
          }
          PrimitiveOperation gate;
          gate.type = PrimitiveOperationType::kXor;
          gate.parent_a = w0.value();
          gate.parent_b = w1.value();
          wire_map[out_ext] = add_gate(gate);
        } else if (identifier == 'A') {
          if ((c0 && !*c0) || (c1 && !*c1)) {
            map_wire(out_ext);
            const_map[out_ext] = false;
            break;
          }
          if (c0 && *c0) {
            wire_map[out_ext] = w1.value();
            break;
          }
          if (c1 && *c1) {
            wire_map[out_ext] = w0.value();
            break;
          }
          PrimitiveOperation gate;
          gate.type = PrimitiveOperationType::kAnd;
          gate.parent_a = w0.value();
          gate.parent_b = w1.value();
          wire_map[out_ext] = add_gate(gate);
        } else {  // OR
          if ((c0 && *c0) || (c1 && *c1)) {
            map_wire(out_ext);
            const_map[out_ext] = true;
            break;
          }
          if (c0 && !*c0) {
            wire_map[out_ext] = w1.value();
            break;
          }
          if (c1 && !*c1) {
            wire_map[out_ext] = w0.value();
            break;
          }
          PrimitiveOperation gate;
          gate.type = PrimitiveOperationType::kOr;
          gate.parent_a = w0.value();
          gate.parent_b = w1.value();
          wire_map[out_ext] = add_gate(gate);
        }
        break;
      }
      case 'M': {
        char tag;
        ss >> tag;
        long long in0_ext = 0, in1_ext = 0, sel_ext = 0, out_ext = 0;
        if (!(ss >> in0_ext >> in1_ext >> sel_ext >> out_ext)) {
          throw std::runtime_error("Malformed MUX gate definition in ABY file");
        }

        const auto c0 = get_const(in0_ext);
        const auto c1 = get_const(in1_ext);
        const auto csel = get_const(sel_ext);
        const auto w0 = c0 ? std::nullopt : std::optional<std::size_t>(map_wire(in0_ext));
        const auto w1 = c1 ? std::nullopt : std::optional<std::size_t>(map_wire(in1_ext));
        const auto wsel = csel ? std::nullopt : std::optional<std::size_t>(map_wire(sel_ext));

        if (csel) {
          if (*csel) {
            if (c1) {
              map_wire(out_ext);
              const_map[out_ext] = *c1;
            } else {
              wire_map[out_ext] = w1.value();
            }
          } else {
            if (c0) {
              map_wire(out_ext);
              const_map[out_ext] = *c0;
            } else {
              wire_map[out_ext] = w0.value();
            }
          }
          break;
        }

        if (w0 && w1 && *w0 == *w1) {
          wire_map[out_ext] = *w0;
          break;
        }

        if (c0 && c1) {
          map_wire(out_ext);
          const_map[out_ext] = *csel ? *c1 : *c0;
          break;
        }

        if (c0 || c1) {
          throw std::runtime_error("MUX with constant data inputs in ABY file is not supported");
        }

        PrimitiveOperation gate;
        gate.type = PrimitiveOperationType::kMux;
        gate.parent_a = w0.value();
        gate.parent_b = w1.value();
        gate.selection_bit = wsel.value();
        wire_map[out_ext] = add_gate(gate);
        break;
      }
      case 'I': {
        char tag;
        ss >> tag;
        long long in_ext = 0, out_ext = 0;
        if (!(ss >> in_ext >> out_ext)) {
          throw std::runtime_error("Malformed INV gate definition in ABY file");
        }

        if (auto c = get_const(in_ext)) {
          map_wire(out_ext);
          const_map[out_ext] = !*c;
          break;
        }

        PrimitiveOperation gate;
        gate.type = PrimitiveOperationType::kInv;
        gate.parent_a = map_wire(in_ext);
        wire_map[out_ext] = add_gate(gate);
        break;
      }
      default:
        break;
    }
  }

  // Resize constant_wires and fill values
  algorithm_description.constant_wires.assign(next_wire_id, std::nullopt);
  for (const auto& [ext, value] : const_map) {
    auto it = wire_map.find(ext);
    if (it == wire_map.end()) continue;
    algorithm_description.constant_wires.at(it->second) = value;
  }

  if (server_inputs > 0 && client_inputs > 0) {
    algorithm_description.number_of_input_wires_parent_a = server_inputs;
    algorithm_description.number_of_input_wires_parent_b = client_inputs;
  } else {
    algorithm_description.number_of_input_wires_parent_a = server_inputs + client_inputs;
    algorithm_description.number_of_input_wires_parent_b = std::nullopt;
  }

  algorithm_description.number_of_gates = algorithm_description.gates.size();
  algorithm_description.number_of_wires = next_wire_id;

  return algorithm_description;
}

}  // namespace encrypto::motion
