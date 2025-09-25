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
/// ```rust
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

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
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
        },
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                &input,
                "ConsensusEncoding cannot be derived for enums yet",
            )
            .to_compile_error()
            .into();
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

    let expanded = quote! {
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
    };

    TokenStream::from(expanded)
}
