//! Procedural macros for consensus encoding and decoding.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Derives `Encodable` and `Decodable` traits for consensus encoding.
///
/// This macro automatically implements both traits by encoding/decoding
/// all fields in declaration order.
///
/// # Example
///
/// ```ignore
/// use consensus_derive::ConsensusEncoding;
///
/// #[derive(ConsensusEncoding)]
/// struct BlockHeader {
///     version: u32,
///     prev_blockhash: [u8; 32],
///     merkle_root: [u8; 32],
///     timestamp: u32,
///     bits: u32,
///     nonce: u32,
/// }
/// ```
#[proc_macro_derive(ConsensusCodec)]
pub fn derive_consensus_encoding(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = match &input.data {
        Data::Struct(data) => {
            let fields = match &data.fields {
                Fields::Named(fields) => &fields.named,
                Fields::Unnamed(fields) => &fields.unnamed,
                Fields::Unit => {
                    return syn::Error::new_spanned(
                        &input,
                        "ConsensusEncoding cannot be derived for unit structs",
                    )
                    .to_compile_error()
                    .into();
                }
            };

            // Generate field access patterns
            let field_accesses: Vec<_> = fields
                .iter()
                .enumerate()
                .map(|(i, field)| {
                    if let Some(ident) = &field.ident {
                        // Named fields: self.field_name
                        quote! { self.#ident }
                    } else {
                        // Tuple fields: self.0, self.1, etc.
                        let index = syn::Index::from(i);
                        quote! { self.#index }
                    }
                })
                .collect();

            // Generate field construction patterns for decoding
            let field_constructions: Vec<_> = fields.iter().map(|field| {
                if let Some(ident) = &field.ident {
                    // Named fields: field_name: Decodable::consensus_decode(reader)?
                    quote! {
                        #ident: crate::consensus::Decodable::consensus_decode_from_finite_reader(reader)?
                    }
                } else {
                    // Tuple fields: just the decoded value
                    quote! {
                        crate::consensus::Decodable::consensus_decode_from_finite_reader(reader)?
                    }
                }
            }).collect();

            let field_constructions_limited: Vec<_> = fields
                .iter()
                .map(|field| {
                    if let Some(ident) = &field.ident {
                        quote! {
                            #ident: crate::consensus::Decodable::consensus_decode(&mut limited_reader)?
                        }
                    } else {
                        quote! {
                            crate::consensus::Decodable::consensus_decode(&mut limited_reader)?
                        }
                    }
                })
                .collect();

            // Determine constructor syntax (struct vs tuple)
            let constructor = if fields.iter().any(|f| f.ident.is_some()) {
                // Named fields
                quote! { #name { #(#field_constructions),* } }
            } else {
                // Tuple fields
                quote! { #name(#(#field_constructions),*) }
            };

            let constructor_limited = if fields.iter().any(|f| f.ident.is_some()) {
                quote! { #name { #(#field_constructions_limited),* } }
            } else {
                quote! { #name(#(#field_constructions_limited),*) }
            };

            quote! {
                impl #impl_generics crate::consensus::Encodable for #name #ty_generics #where_clause {
                    #[inline]
                    fn consensus_encode<W: crate::io::Write + ?Sized>(
                        &self,
                        writer: &mut W,
                    ) -> core::result::Result<usize, crate::io::Error> {
                        let mut len = 0;
                        #(
                            len += #field_accesses.consensus_encode(writer)?;
                        )*
                        Ok(len)
                    }
                }

                impl #impl_generics crate::consensus::Decodable for #name #ty_generics #where_clause {
                    #[inline]
                    fn consensus_decode_from_finite_reader<R: crate::io::Read + ?Sized>(
                        reader: &mut R,
                    ) -> core::result::Result<Self, crate::consensus::EncodeDecodeError> {
                        Ok(#constructor)
                    }

                    #[inline]
                    fn consensus_decode<R: crate::io::Read + ?Sized>(
                        reader: &mut R,
                    ) -> core::result::Result<Self, crate::consensus::EncodeDecodeError> {
                        use crate::io::Read;
                        let mut limited_reader = reader.take(crate::consensus::MAX_VEC_SIZE as u64);
                        Ok(#constructor_limited)
                    }
                }
            }
        }
        Data::Enum(data) => {
            // Generate match arms for encoding
            let encode_arms: Vec<_> = data.variants.iter().enumerate().map(|(i, variant)| {
                let variant_name = &variant.ident;
                #[allow(clippy::cast_possible_truncation, reason = "i is always small enough to fit in u8")]
                let discriminator = i as u8;

                match &variant.fields {
                    Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                        // Single tuple field variant
                        quote! {
                            #name::#variant_name(msg) => {
                                let mut len = #discriminator.consensus_encode(writer)?;
                                len += msg.consensus_encode(writer)?;
                                Ok(len)
                            }
                        }
                    }
                    Fields::Unit => {
                        // Unit variant
                        quote! {
                            #name::#variant_name => {
                                #discriminator.consensus_encode(writer)
                            }
                        }
                    }
                    _ => {
                        // Other field types not supported for enums
                        quote! {
                            compile_error!("Only unit variants and single-field tuple variants are supported for enums")
                        }
                    }
                }
            }).collect();

            // Generate match arms for decoding
            let decode_arms: Vec<_> = data.variants.iter().enumerate().map(|(i, variant)| {
                let variant_name = &variant.ident;
                #[allow(clippy::cast_possible_truncation, reason = "i is always small enough to fit in u8")]
                let discriminator = i as u8;

                match &variant.fields {
                    Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                        // Single tuple field variant
                        quote! {
                            #discriminator => {
                                let msg = crate::consensus::Decodable::consensus_decode_from_finite_reader(reader)?;
                                Ok(#name::#variant_name(msg))
                            }
                        }
                    }
                    Fields::Unit => {
                        // Unit variant
                        quote! {
                            #discriminator => Ok(#name::#variant_name)
                        }
                    }
                    _ => {
                        // Other field types not supported for enums
                        quote! {
                            compile_error!("Only unit variants and single-field tuple variants are supported for enums")
                        }
                    }
                }
            }).collect();

            // Generate error message for invalid variant
            let variant_count = data.variants.len();
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "variant_count is always at least 1 for enums"
            )]
            let max_variant = variant_count - 1;
            let error_msg = format!(
                "Invalid variant for {} enum (expected 0-{})",
                name, max_variant
            );

            quote! {
                impl #impl_generics crate::consensus::Encodable for #name #ty_generics #where_clause {
                    fn consensus_encode<W: crate::io::Write + ?Sized>(
                        &self,
                        writer: &mut W,
                    ) -> core::result::Result<usize, crate::io::Error> {
                        match self {
                            #(#encode_arms),*
                        }
                    }
                }

                impl #impl_generics crate::consensus::Decodable for #name #ty_generics #where_clause {
                    fn consensus_decode_from_finite_reader<R: crate::io::Read + ?Sized>(
                        reader: &mut R,
                    ) -> core::result::Result<Self, crate::consensus::EncodeDecodeError> {
                        let variant = u8::consensus_decode_from_finite_reader(reader)?;

                        match variant {
                            #(#decode_arms),*
                            _ => Err(crate::consensus::EncodeDecodeError::ParseFailed(
                                #error_msg
                            )),
                        }
                    }

                    fn consensus_decode<R: crate::io::Read + ?Sized>(
                        reader: &mut R,
                    ) -> core::result::Result<Self, crate::consensus::EncodeDecodeError> {
                        use crate::io::Read;
                        let mut limited_reader = reader.take(crate::consensus::MAX_VEC_SIZE as u64);
                        Self::consensus_decode_from_finite_reader(&mut limited_reader)
                    }
                }
            }
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(
                &input,
                "ConsensusEncoding cannot be derived for unions",
            )
            .to_compile_error()
            .into();
        }
    };

    TokenStream::from(expanded)
}
